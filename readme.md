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
