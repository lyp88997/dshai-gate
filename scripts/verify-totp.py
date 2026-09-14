#!/usr/bin/env python3
"""独立校验 TOTP 动态码（RFC6238: SHA1/30s/6位），容差 ±1 个时间片。
用法: verify-totp.py <base32密钥> <6位码>   → 退出码 0=通过 1=不通过"""
import base64, hashlib, hmac, struct, sys, time

def main() -> int:
    if len(sys.argv) < 3:
        return 2
    raw = sys.argv[1].strip().replace(" ", "").upper()
    raw += "=" * ((8 - len(raw) % 8) % 8)
    try:
        key = base64.b32decode(raw)
    except Exception:
        return 1
    code = sys.argv[2].strip().replace(" ", "")
    if len(code) != 6 or not code.isdigit():
        return 1
    now = int(time.time()) // 30
    for d in (0, -1, 1):
        c = now + d
        if c < 0:
            continue
        mac = hmac.new(key, struct.pack(">Q", c), hashlib.sha1).digest()
        off = mac[-1] & 0x0F
        val = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % 1000000
        if "%06d" % val == code:
            return 0
    return 1

sys.exit(main())
