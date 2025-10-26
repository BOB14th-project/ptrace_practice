## 
https://tartanllama.xyz/posts/writing-a-linux-debugger/breakpoints/

디버거 작동 학습

먹이로 쓰자

## 01. 기본 세팅

## 02. SW breakpoint
objdump로 심볼 주소를 뽑고, ASLR끄고 브레이크포인트 거는 방식

## ASLR 을 끄지 않았을때
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

