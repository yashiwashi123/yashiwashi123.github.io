**Background** Stealc analysis has been an on again off again project over the past year. 

Here is a config extractor
```python

import re
import base64
from Crypto.Cipher import ARC4
import sys

# Helper: check if decrypted bytes look like readable text

def looks_text(b: bytes):
    try:
        s = b.decode("utf-8")
        # basic sanity check
        if any(ord(c) < 9 for c in s):
            return False
        return True
    except:
        return False

# Key-block pattern 
# Generally with shitty malware like this where they automate builds, they have a block where they write it too and it's buffered out usually consistant in length 
keyblock_pattern = re.compile(
    rb"string too long"
    rb"\x00+"
    rb"(?P<prefix>[ -~]+?)"     # ASCII prefix (non-greedy)
    rb"\x00{2,}"
    rb"(?P<hexkey>[0-9a-f]{16})"       # 16 lowercase hex chars
    rb"\x00{2,}"
    rb"(?P<alpha10>[A-Za-z0-9]{10})"      # 10 alphabetic RC4 key
    rb"\x00+"
)

# Base64 finder
b64_regex = re.compile(rb"[A-Za-z0-9+/]{8,}={0,2}")

# URL and URI extractors
url_regex = re.compile(r"https?://[A-Za-z0-9._:/\-]+")
php_regex = re.compile(r"/[A-Za-z0-9._/\-]+\.php")



def scan_file(path):
    with open(path, "rb") as f:
        data = f.read()

    # ---- extract keys ----
    m = keyblock_pattern.search(data)
    if not m:
        print("[!] No key-block found.")
        return None

    prefix  = m.group("prefix").decode(errors="ignore")
    hexkey  = m.group("hexkey").decode()
    rc4_key = m.group("alpha10")  # bytes (10 ASCII letters)

    print("[+] Extracted key block:")
    print(f"    botid:   {prefix}")
    print(f"    traffic key:   {hexkey}")
    print(f"    string key:  {rc4_key}")

    found_url = None
    found_php = None

    # ---- scan for base64 + RC4 decode ----
    for hit in b64_regex.finditer(data):
        b64_raw = hit.group()

        # Try base64 decode
        try:
            decoded = base64.b64decode(b64_raw, validate=False)
        except:
            continue

        # RC4 decrypt using PyCryptodome
        try:
            cipher = ARC4.new(rc4_key)
            pt = cipher.decrypt(decoded)
        except:
            continue

        if not looks_text(pt):
            continue

        text = pt.decode("utf-8", "ignore")

        # See if this decrypted string contains a URL
        if not found_url:
            m_url = url_regex.search(text)
            if m_url:
                found_url = m_url.group(0)

        # See if this decrypted string contains a .php URI
        if not found_php:
            m_php = php_regex.search(text)
            if m_php:
                found_php = m_php.group(0)

        # Stop early if both found
        if found_url and found_php:
            break

    result = {
        "botid": prefix,
        "traffic rc4 key": hexkey,
        "string rc4 key": rc4_key.decode("ascii"),
        "url": found_url,
        "uri": found_php,
    }

    print("\n[+] Final extracted data:")
    for k, v in result.items():
        print(f"  {k}: {v}")

    return result


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <pe_file>")
        sys.exit(1)
    scan_file(sys.argv[1])


```