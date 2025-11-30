
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
import sys
import time

# ==========================================================
# [설정] 서버 접속 정보
# ==========================================================
HOST = 'host8.dreamhack.games' 
PORT = 17897 

def solve():
    # 무한 루프: 성공할 때까지 재접속
    while True:
        try:
            print(f"\n[+] Connecting to {HOST}:{PORT}...")
            r = remote(HOST, PORT)
            
            # 1. 암호문 획득
            r.sendlineafter(b'Menu >> ', b'1')
            response = r.recvline().strip().decode()
            
            if len(response) != 96:
                print("[-] Invalid response length. Retrying...")
                r.close()
                continue
                
            real_iv = bytes.fromhex(response[:32])
            target_ct = bytes.fromhex(response[32:64]) # Token Block
            
            print(f"[+] Got Ciphertext. Real IV: {real_iv.hex()}")
            
            intermediate = bytearray(16)
            failed_session = False
            
            # 2. Byte-by-Byte Decryption (15 -> 0)
            for byte_index in range(15, -1, -1):
                padding_value = 16 - byte_index
                
                # 진행 상황 출력
                sys.stdout.write(f"\r[*] Cracking byte {byte_index} (Pad: {padding_value})... ")
                sys.stdout.flush()
                
                found_byte = False
                
                # 이미 찾은 뒷부분 세팅
                base_iv = bytearray(16)
                for k in range(byte_index + 1, 16):
                    base_iv[k] = intermediate[k] ^ padding_value
                
                # 0x00 ~ 0xFF 브루트포스
                for val in range(256):
                    base_iv[byte_index] = val
                    
                    # --- Oracle Logic ---
                    # 인덱스 0일 때는 캐시 우회 불가 (한방에 성공해야 함)
                    # 인덱스 1~15일 때는 IV[0]을 바꿔서 캐시 우회 가능
                    
                    test_iv = bytearray(base_iv)
                    dummy_idx = 0
                    
                    is_valid = False
                    
                    # 캐시 우회 루프 (인덱스 0이 아닐 때만 유효)
                    while True:
                        payload = test_iv.hex().encode() + target_ct.hex().encode()
                        r.sendlineafter(b'Menu >> ', b'2')
                        r.sendlineafter(b'Ciphertext (hex) >> ', payload)
                        
                        res = r.recvline().strip().decode()
                        
                        if res == 'True':
                            is_valid = True
                            break
                        elif res == 'False':
                            is_valid = False
                            break
                        else: # None (Cache Hit/Drop)
                            if byte_index == 0:
                                # [중요] Byte 0에서는 IV를 바꿀 수 없음. 
                                # 정답인데 None이 떴다면 이 세션은 망한 것임.
                                is_valid = False # 루프를 계속 돌게 둠 (혹시 다른 val이 정답일까봐)
                                break 
                            else:
                                # Byte 1~15는 IV[0]을 바꿔서 재시도
                                test_iv[dummy_idx] = (test_iv[dummy_idx] + 1) % 256
                    
                    if is_valid:
                        intermediate[byte_index] = val ^ padding_value
                        found_byte = True
                        # sys.stdout.write(f" Found: {hex(intermediate[byte_index])}")
                        break
                
                if not found_byte:
                    print(f"\n[-] Failed to crack byte {byte_index}. (Bad luck with 50% drop)")
                    failed_session = True
                    break # inner for loop break
            
            if failed_session:
                print("[-] Restarting session...")
                r.close()
                continue # while True continue
            
            # 3. 모든 바이트 복구 완료
            token = bytes([intermediate[i] ^ real_iv[i] for i in range(16)])
            print(f"\n[+] Decryption complete!")
            print(f"[+] Token: {token.hex()}")
            
            # 4. 정답 제출
            r.sendlineafter(b'Menu >> ', b'3')
            r.sendlineafter(b'Answer (hex) >> ', token.hex().encode())
            
            flag_res = r.recvall().decode()
            if "DH{" in flag_res:
                print(f"\n{'='*40}")
                print(flag_res.strip())
                print(f"{'='*40}")
                r.close()
                return # 종료
            else:
                print(f"[-] Something went wrong: {flag_res}")
                r.close()
                
        except EOFError:
            print("[-] Server disconnected unexpectedly.")
            r.close()
        except KeyboardInterrupt:
            print("\n[*] Aborted by user.")
            exit()
        except Exception as e:
            print(f"[-] Error: {e}")
            if 'r' in locals(): r.close()

if __name__ == '__main__':
    solve()

```


# Solve
![[❤️ WriteUps/reversing/swap/image1.png]]

