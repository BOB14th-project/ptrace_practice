## 
https://tartanllama.xyz/posts/writing-a-linux-debugger/breakpoints/

디버거 작동 학습

먹이로 쓰자

## 01. 기본 세팅

## 02. SW breakpoint
objdump로 심볼 주소를 뽑고, ASLR끄고 브레이크포인트 거는 방식

### ASLR 을 끄지 않았을때
2개의 터미널을 띄우고 한 터미널에서 ./minidbg ./target 을 실행한뒤에 다른 프롬프트에서 진행

```bash
➜  02.swbreakpoint git:(master) ✗ pid=$(pgrep -n target)
➜  02.swbreakpoint git:(master) ✗ echo "PID=$pid"
PID=20533
➜  02.swbreakpoint git:(master) ✗ head -n1 /proc/$pid/maps
555555554000-555555555000 r--p 00000000 00:45 10977524091715716          /mnt/d/git/ptrace_practice/02.swbreakpoint/target
➜  02.swbreakpoint git:(master) ✗ python3 - << 'PY'
base = int('555555554000',16)
offset = int('1169',16)
print(hex(base+offset))
PY
0x555555555169
```
PID를 찾고, 맵을 읽어서 text 베이스주소를 찾는다
그리고 오프셋을 더해서 실제 브레이크 주소를 구한다

```bash
➜  02.swbreakpoint git:(master) ✗ nm -n target |
grep main
                 U __libc_start_main@GLIBC_2.34
0000000000001169 T main
```
이게 오프셋

```bash
➜  02.swbreakpoint git:(master) ✗ ./minidbg ./target
minidbg> break 0x555555555169
Set breakpoint at address 0x555555555169
minidbg> cont
[stopped] signal 5
minidbg> cont
start
middle
end
[exit] status 0
minidbg>
```

ASLR로 인해서 base address가 랜덤화 되어 오프셋만 아는걸로는 실제 위치를 바로 찾을 수 없다.
그런데 커널이 현재 프로세스의 메모리 배치를 그대로 보여주는 인터페이스가 있으므로, 거기서 베이스 주소를 읽고 오프셋을 더해서 실제 주소를 구할 수 있도록 한다. 이런식이면 ASLR을 일부러 끌 필요가 없다.

### ASLR, PIE를 껐을때

현재 `minidbg`는 자식 프로세스에서 `personality(ADDR_NO_RANDOMIZE)`를 호출해 ASLR을 비활성화한다. 그러면 커널이 베이스 주소를 랜덤화 하지 않음

그리고 빌드 옵션으로 PIE를 끄자, PIE는 실행 파일 전체를 위치 독립적 코드로 만드는 빌드 방식으로 텍스트/데이터 세그먼트가 특정 가상 주소에 묶이지 않고 어떤 베이스 주소로 로드되어도 정상 동작하게 하는것. 기존에는 PIE로 인해 파일 안의 오프셋 = 런타임 주소가 성립하지 않았다

-no-pie로 빌드하면 실행 파일이 ET_DYN이 아닌 고정베이스로 링크되므로 로더가 어떤 주소에도 자유롭게 옮겨야 할 필요가 없어진다

두 조건이 동시에 맞으면 파일 안에서 오프셋과 런타임 주소가 일대일로 매칭된다.

```bash
➜  02.swbreakpoint git:(master) ✗ nm -n target | grep main
                 U __libc_start_main@GLIBC_2.34
0000000000401156 T main
➜  02.swbreakpoint git:(master) ✗ ./minidbg ./target
minidbg> break 0x401156
Set breakpoint at address 0x401156
minidbg> cont
[stopped] signal 5
minidbg> cont
start
middle
end
[exit] status 0
```

임의 프로그램을 직접 실행할 때는 setarch -R 또는 personality(ADDR_NO_RANDOMIZE)로 ASLR을 끄거나, 위 ASLR 켠 상태의 절차처럼 `/proc/<pid>/maps` 기반으로 주소를 계산하는 것 중 필요한 쪽을 골라 쓰면 된다.......

## 03. register_and_memory

```bash
➜  03.register_and_memory git:(master) ✗ ./minidbg ./target
minidbg> break 0x555555555169
Set breakpoint at address 0x555555555169
minidbg> cont
[stopped] signal 5
minidbg> cont
start
middle
end
[exit] status 0
minidbg>
```
02번 디버거와 기본 흐름은 같지만, `register dump/read/write`와 `memory read/write` 명령으로 레지스터·메모리를 직접 다루고, 브레이크포인트 복구를 위해 `PTRACE_SINGLESTEP`과 `rip` 재설정을 수행하며, ptrace 에러를 예외로 보고하고 모든 신호를 로그로 확인할 수 있도록 동작을 확장

그러니까 이전 명령때는 0xcc에서 복구하고 진행하는 기능이 없었다는것. 02번 디버거는 이후 명령이 깨지거나 이상현상이 있을 수 있었다.

## 04. Elves_and_Dwarves
ELF + DWARF 정보로 파일:라인에서 실제 코드 주소를 찾아서 소스 라인 브레이크포인트를 걸 수 있다고 한다

예제 코드는 없음

1. DWARF 열기
- 실행파일 또는 해당 .so의 .debug_line 섹션 파싱
여러 컴파일 유닛(CU) 중에서 파일 경로가 일치하는 - - 라인 테이블 선택(경로 normalize 주의: 상대/절대, 디렉터리 엔트리 분리됨) ????????? - 나중에 설명 추가하기

2. 라인 -> 링크 타임 주소 결정
- 라인 테이블의 행들 중 (file == F, line == L) 에 해당하는 statememt 시작 (is_stmt=true) 항목을 고름
- 가능하면 prologue_end 표식(PE)이 붙은 지점을 선호(함수 프롤로그를 넘긴 첫 명령에 걸려서 스텝의 품질이 좋아진다)
- 인라인/최적화로 같은 라인에 여러 주소가 있을 수 있는데 -> 보통 가장 작은 주소나 is_stmt/PE 를 우선

3. ASLR/PIE 보정(런타임 주소 계산)
- 대상 바이너리가 PIE거나 공유 라이브러리면, 링크타임 주소 그대로 쓰면 안되고
- 디버깅 중인 프로세스 /proc/<pid>/maps에서 해당 객체의 로드 베이스를 구함(예: libfoo.so가 0x7f...000에 매핑).
- runtime_addr = load_base + (link_addr - link_base) 로 보정 (비-PIE 실행 파일은 보통 load_base == link_base라 보정 불필요.)

이 부분은 02번에서 했던것 같다

4. breakpoint 설치
- 계산된 runtime_addr에 한 바이트를 저장해 두고(원바이트 백업), 0xCC로 패치
- 히트 시에는 이전에 설명한 BP 넘기기 루틴(원바이트 복원→RIP=bp_addr→싱글스텝→재설치)을 적용.

이 부분이 03번에서 진행한것

5. 함수명으로 브레이크 포인트를 건다면??
- 심볼이 살아 있으면 .symtab/.dynsym에서 함수 이름으로 엔트리 주소를 얻고, 위와 같은 PIE 보정 후 BP를 심을 수 있어.
- 심볼이 없더라도 DWARF의 .debug_info에서 DW_TAG_subprogram(함수 DIE) 의 low_pc/high_pc로 함수 시작 주소를 얻는 방법도 있음.

이 부분은 아직 실습 안함

### 변수의 내용을 읽는 법
- DW_AT_location : 변수가 어디에 있는지 알려주는 위치 표현식/목록
- DW_AT_frame_base : frame base가 어디인지 알려주는 표현식/목록

하면서 내용 수정...

## 05. Source and Signals

### run()과 초기화 흐름
- `debugger` 생성자는 실행 파일을 `open(O_RDONLY)`으로 연 뒤 libelfin 로더를 사용해 `m_elf`, `m_dwarf`를 초기화하고, FD는 즉시 닫는다. 이후 모든 DWARF 조회가 이 핸들을 재사용한다.
- `run()`은 최초 `wait_for_signal(false)`로 exec 직후 SIGTRAP을 받아들이고, 조기 종료/시그널을 체크한 다음 `initialize_load_address()`로 PIE 오프셋을 준비한다. 이어서 `PTRACE_SETOPTIONS`(EXITKILL, TRACESYSGOOD)를 걸고 REPL을 시작한다.

### 세부 함수 메모

```cpp
void debugger::initialize_load_address() {
    m_load_address = 0;

    if (m_elf.get_hdr().type != elf::et::dyn) {
        return;
    }

    std::ifstream map("/proc/" + std::to_string(m_pid) + "/maps");
    if (!map) {
        report_error("failed to open /proc/" + std::to_string(m_pid) + "/maps");
        return;
    }

    std::string addr;
    if (std::getline(map, addr, '-')) {
        try {
            m_load_address = std::stoull(addr, nullptr, 16);
        } catch (const std::exception& ex) {
            report_error(std::string("failed to parse load address: ") + ex.what());
        }
    } else {
        report_error("unexpected format while reading load address");
    }
}
```
대상 프로세스의 로드 베이스 주소를 계산한다. `run()` 입구에서 한 번 호출되며, ELF 타입이 `ET_DYN`이 아닐 경우 그대로 0을 유지한다. `/proc/<pid>/maps` 첫 매핑의 시작 주소를 파싱해 `m_load_address`에 저장하고, 읽기/파싱 실패는 `report_error`로 기록한다.

```cpp
uint64_t debugger::offset_load_address(uint64_t addr) const {
    if (m_load_address == 0 || addr < m_load_address) {
        return addr;
    }
    return addr - m_load_address;
}
```
PIE 바이너리와 공유 라이브러리에서만 로드 베이스를 빼고, 그렇지 않은 경우(비-PIE, 이미 보정된 주소)는 그대로 돌려준다. `addr < m_load_address` 같은 비정상 상황도 그냥 원본 주소를 반환하도록 방어 로직을 둔 상태.

```cpp
dwarf::die debugger::get_function_from_pc(uint64_t pc) {
    for (auto &cu : m_dwarf.compilation_units()) {
        if (die_pc_range(cu.root()).contains(pc)) {
            for (const auto& die : cu.root()) {
                if (die.tag == dwarf::DW_TAG::subprogram) {
                    if (die_pc_range(die).contains(pc)) {
                        return die;
                    }
                }
            }
        }
    }
    throw std::out_of_range{"Cannot find function"};
}
```
특정 PC가 속한 함수(`DW_TAG::subprogram`) DIE를 찾는다. 현재는 선형 탐색이라 단순하지만 브레이크/스텝 정지 시 함수명 확인, 향후 스코프 분석 등에 바로 활용 가능하다. 인라인 함수나 LTO 결과까지 엄밀히 처리하려면 추가 로직이 필요하다.

```cpp
dwarf::line_table::iterator debugger::get_line_entry_from_pc(uint64_t pc) {
    for (auto &cu : m_dwarf.compilation_units()) {
        if (die_pc_range(cu.root()).contains(pc)) {
            auto& lt = cu.get_line_table();
            auto it = lt.find_address(pc);
            if (it == lt.end()) {
                throw std::out_of_range{"Cannot find line entry"};
            }
            return it;
        }
    }
    throw std::out_of_range{"Cannot find line entry"};
}
```
PC에 대응하는 라인 테이블 엔트리를 반환한다(파일 경로, 라인 번호 포함). 정지 시 소스 콘텍스트를 뽑는 기본 자료로 쓰이며, 주소가 정확히 매칭되지 않으면 `std::out_of_range`를 던져 호출자에게 처리를 맡긴다. 최적화 수준이 높을수록 테이블 자체가 비어 있을 수 있다는 점만 주의하면 된다.

```cpp
void debugger::print_source(const std::string& file_name, unsigned line, unsigned n_lines_context){
    std::ifstream file{file_name};
    if (!file) {
        report_error("failed to open source file: " + file_name);
        return;
    }

    // Work out a window around the desired line
    auto start_line = line <= n_lines_context ? 1 : line - n_lines_context;
    auto end_line = line + n_lines_context + (line < n_lines_context ? n_lines_context - line : 0) + 1;

    char c{};
    auto current_line = 1u;
    // Skip lines up until start_line
    while (current_line != start_line && file.get(c)) {
        if (c == '\n') {
            ++current_line;
        }
    }

    if (current_line > end_line) {
        return;
    }

    std::cout << (current_line == line ? "> " : "  ");

    // Write lines up until end_line
    while (current_line <= end_line && file.get(c)) {
        std::cout << c;
        if (c == '\n') {
            ++current_line;
            // Output cursor if we are at the current line
            std::cout << (current_line == line ? "> " : "  ");
        }
    }

    std::cout << std::endl;
}
```
지정된 파일의 주변 라인을 출력하며 현재 라인을 `>`로 강조한다. 파일 열기에 실패하면 바로 에러를 신고하고 조용히 리턴한다. 브레이크포인트나 단일 스텝에서 멈춘 직후 호출된다.

```cpp
siginfo_t debugger::get_signal_info() {
    siginfo_t info{};
    if (ptrace(PTRACE_GETSIGINFO, m_pid, nullptr, &info) == -1) {
        perror("ptrace(PTRACE_GETSIGINFO)");
        std::memset(&info, 0, sizeof(info));
    }
    return info;
}
```
`waitpid`로 STOP 상태를 확인한 직후 호출해 마지막 신호의 `siginfo_t`를 얻는다. `PTRACE_GETSIGINFO`가 실패하면 errno 로그를 남기고 0으로 초기화된 구조체를 반환해 이후 로직이 무너지는 것을 방지한다.

```cpp
void debugger::handle_sigtrap(siginfo_t info) {
    switch (info.si_code) {
    //one of these will be set if a breakpoint was hit
    case SI_KERNEL:
    case TRAP_BRKPT:
    {
        const auto pc = get_pc() - 1;
        set_pc(pc); // put the pc back where it should be
        std::cout << "Hit breakpoint at address 0x" << std::hex << pc << std::dec << '\n';

        const auto offset_pc = offset_load_address(pc);
        try {
            auto line_entry = get_line_entry_from_pc(offset_pc);
            print_source(line_entry->file->path, line_entry->line, 2);
        } catch (const std::exception& ex) {
            report_error(std::string("failed to print source: ") + ex.what());
        }
        return;
    }
    //this will be set if the signal was sent by single stepping
    case TRAP_TRACE:
        return;
    default:
        std::cout << "Unknown SIGTRAP code " << info.si_code << std::endl;
        return;
    }
}
```
SIGTRAP 원인 분기 처리하는 함수

1. get_pc()로 현재 RIP/PC 읽고
2. 소프트웨어 BP(int3 = 0xcc) 있으므로 PC-1을 보정한다
3. 보정된 PC를 로드 오프셋으로 조정한 뒤 `get_line_entry_from_pc()` → `print_source()`를 통해 현재 소스 문맥을 출력한다
4. 단일 스텝 복구는 `continue`/`next` 등의 명령에서 `step_over_breakpoint()`가 담당한다

x86외 아키텍쳐 BP는 별도 처리가 필요하다

```cpp
int debugger::wait_for_signal(bool report) {
    int wait_status = 0;
    if (waitpid(m_pid, &wait_status, 0) < 0) {
        perror("waitpid");
        return -1;
    }

    if (WIFEXITED(wait_status)) {
        if (report) {
            std::cout << "[exit] status " << WEXITSTATUS(wait_status) << '\n';
        }
        return wait_status;
    }

    if (WIFSIGNALED(wait_status)) {
        if (report) {
            std::cout << "[killed] by signal " << WTERMSIG(wait_status) << '\n';
        }
        return wait_status;
    }

    if (WIFSTOPPED(wait_status)) {
        const auto sig = WSTOPSIG(wait_status);
        const auto info = get_signal_info();

        switch (sig) {
        case SIGTRAP:
            handle_sigtrap(info);
            break;
        case SIGSEGV:
            if (report) {
                std::cout << "Received SIGSEGV (code " << info.si_code
                          << ") at address 0x" << std::hex
                          << reinterpret_cast<std::uintptr_t>(info.si_addr)
                          << std::dec << '\n';
            }
            break;
        default:
            if (report) {
                std::cout << "Stopped by signal " << strsignal(sig) << '\n';
            }
            break;
        }
    }

    return wait_status;
}
```
waitpid 루프의 중앙 허브, 정지 원인에 따라서 분기한다
1. waitpid(m_pid, &status, 0)
2. WIFSTOPPED(status) 면 get_signal_info()
3. info.si_signo에 따라서
    - SIGTRAP > handle_sigtrap(info)
    - SIGSEGV > si_code/주소 로그(옵션으로 메모리 덤프)
    - 기타 > `strsignal`로 간단히 알림

```cpp
void debugger::step_over_breakpoint() {
    const auto it = m_breakpoints.find(get_pc());
    if (it == m_breakpoints.end()) {
        return;
    }

    auto& bp = it->second;
    if (!bp.is_enabled()) {
        return;
    }

    bp.disable();
    if (ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr) == -1) {
        perror("ptrace(PTRACE_SINGLESTEP)");
    } else {
        wait_for_signal(false);
    }
    bp.enable();
}
```
히트한 BP를 한번 우회하는 표준 루틴
BP 해제 → `PTRACE_SINGLESTEP` → 재대기 → BP 재설치 순서로 진행한다.
`continue`나 다른 실행 명령이 재개되기 전에 호출돼, 방금 히트한 소프트웨어 브레이크포인트를 원래 명령으로 되돌린다.

### 실행 흐름 예시 - SW breakpoint hit
1. target int3 도달 > SIGTRAP/TRAP_BPKPT 정지
2. wait_for_signal() > get_signal_info() > handle_sigtrap()
3. get_pc > set_pc(pc-1) (0xcc 보정)
4. 사용자가 `continue` 등을 호출하면 step_over_breakpoint()가 원본 바이트를 복구하고 단일 스텝 후 재설치
5. get_line_entry_from_pc() > print_source() 로 현재 소스 표시
6. 사용자 입력 루프 (계속/다음 스텝/다른 BP 설정 등...)

## 06. 

## 고려해야할 방해 로직들...

- ptrace 감지/배제: ptrace(PTRACE_TRACEME) 재호출, getppid() 체크, /proc/self/status의 TracerPid 확인 등으로 디버거 존재를 감지해 종료하거나 기능을 바꿉니다.
- 시그널·예외 조작: SIGTRAP, SIGILL 등을 고의로 발생시켜 디버거가 예상대로 처리하지 못하면 흐름이 깨지게 하거나, 신호 처리기를 덮어쓰기도 합니다.
- 타이밍·성능 체크: 루틴 실행 시간을 반복 측정해 디버깅으로 인해 지연이 늘어나면 다른 코드 경로를 타도록 만듭니다.
- 코드 무결성/셀프체크: 자신을 해시·서명해 두고 변조가 감지되면 종료합니다. 암호 루틴 전후로 키/상태 검사를 넣어 디버가 수정한 흔적을 찾아내기도 합니다.
- 난독화·JIT·특수 ABI: 암호 루틴을 난독화하거나 런타임에 생성해 디버깅을 어렵게 합니다. 커널 모드, 가상화, SGX 등의 보호 영역에서 실행되면 사용자 공간 디버거로는 접근이 힘든 경우도 있습니다.

즉 “ASLR/PIE만 끄면 끝”이 아니라, 표적인 프로그램이 어떤 보호를 구현했는지 먼저 확인하세요. 디버거 회피 로직이 있다면 이를 제거하거나 우회(패치, LD_PRELOAD, 커널 모듈 등)한 뒤 본격적으로 분석하는 순서가 일반적입니다.


- API 후킹으로 감지되는 케이스만 다룬다면 일반적인 ptrace 회피나 시그널 트랩 같은 “디버거 탐지” 로직은 우선순위가 낮습니다. 해당 프로그램이 실제로 쓰는 보호 기법을 먼저 확인하고, 그 범위 안에서만 방어 우회를 준비해도 충분합니다.
- 다만 암호 루틴 자체가 self-integrity 체크나 타이밍 체크를 포함할 가능성은 염두에 두세요. 후킹으로 빠져나간다는 걸 전제로 코드를 바꿔 놓았다면 디버거에서도 같은 조건을 만족시켜야 합니다.
- 즉, API 후킹으로 잡히지 않는 커스텀 암호화 루틴만 디버거로 뜯어보면 된다면, 디버거 회피 로직 추가 여부만 살펴보고 나머지는 과감히 무시해도 괜찮습니다.

먼저 함수 후킹으로 api콜하는거를 잡아내고 직접 구현된 암호화만 이걸로 포착하고 있으니까 몇가지 케이스는 덜 고려해도 되는거 아닌가... 개인적인 생각
