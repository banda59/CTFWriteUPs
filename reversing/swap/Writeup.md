
# 문제
```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  char char128[128]; // [rsp+0h] [rbp-D0h] BYREF
  char char32_2[32]; // [rsp+80h] [rbp-50h] BYREF
  char char32[32]; // [rsp+A0h] [rbp-30h] BYREF
  FILE *stream; // [rsp+C0h] [rbp-10h]
  size_t size; // [rsp+C8h] [rbp-8h]

  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stderr, 0, 2, 0);
  printf("Enter the secret key: ");
  if ( !fgets(char32, 32, stdin) )
  {
    puts("Failed to read input");
    return 1;
  }
  size = strlen(char32);
  if ( size && char32[size - 1] == 10 )
    char32[--size] = 0;
  if ( size != 16 )
  {
    puts("Wrong key length!");
    return 1;
  }
  sub_4011AF((__int64)char32, (__int64)char32_2, 16);
  if ( !memcmp(char32_2, &unk_404070, 0x10u) )
  {
    stream = fopen("flag", "r");
    if ( !stream )
    {
      puts("Flag file not found!");
      return 1;
    }
    if ( fgets(char128, 128, stream) )
      printf("Correct! Here is your flag: %s\n", char128);
    fclose(stream);
  }
  else
  {
    puts("Wrong key!");
  }
  return 0;
}
```



# payload
```python
from pwn import *

# 1. 서버 연결 정보 설정
r = remote('host8.dreamhack.games', 21992)

# 2. Secret Key 복구 (아까 짠 로직)
encrypted_data = [
    0x6F, 0x0D, 0x6E, 0x80, 
    0x10, 0x22, 0xF4, 0x70, 
    0xD5, 0x52, 0x83, 0x74, 
    0x25, 0x16, 0x47, 0x38
]

key = ""
for i in range(16):
    target_byte = encrypted_data[i]
    step1 = (target_byte - i) % 256
    step2 = step1 ^ 0x5A
    final_char = ((step2 >> 4) | (step2 << 4)) & 0xFF
    key += chr(final_char)

print(f"[*] Recovered Key: {key}")

r.sendlineafter(b': ', key.encode())
r.interactive()
```


# Solve
![[/reversing/swap/image1.png]]

