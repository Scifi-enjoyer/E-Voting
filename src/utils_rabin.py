"""
utils_rabin.py
Thư viện hỗ trợ cho demo bỏ phiếu Rabin.
- Các hàm số học (Miller-Rabin, CRT, Jacobi)
- Sinh khóa Rabin (Blum primes)
- Chữ ký Rabin (FDH-style)
- Mã hóa/Giải mã Rabin (padded, chọn root bằng PAD_MARKER)
- Hàm tiện ích lưu/đọc JSON và canonical JSON
"""

import json, secrets, hashlib, unicodedata
from pathlib import Path

# ---------------------------
# Hàm số học cơ bản
# ---------------------------

def is_probable_prime(n, k=8):
    """Kiểm tra số nguyên tố bằng Miller-Rabin."""
    if n < 2:
        return False
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n % p == 0:
            return n == p
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2; s += 1
    for _ in range(k):
        a = secrets.randbelow(n-3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n-1:
            continue
        for __ in range(s-1):
            x = (x * x) % n
            if x == n-1:
                break
        else:
            return False
    return True

def gen_random_odd(bits):
    """Sinh số lẻ có bit cao = 1, đảm bảo độ dài bits."""
    x = secrets.randbits(bits-1) | (1 << (bits-1))
    x |= 1
    return x

def gen_blum_prime(bits):
    """Sinh Blum prime p ≡ 3 (mod 4)."""
    while True:
        p = gen_random_odd(bits)
        p |= 3
        if is_probable_prime(p):
            return p

def crt_combine(rp, rq, p, q):
    """Kết hợp nghiệm modulo p và q thành nghiệm modulo n bằng CRT."""
    n = p * q
    inv_p = pow(p, -1, q)
    x = (rp + (((rq - rp) * inv_p) % q) * p) % n
    return x

def jacobi(a, n):
    """Tính ký hiệu Jacobi (a/n)."""
    if n <= 0 or n % 2 == 0:
        raise ValueError("n phải là số lẻ dương.")
    a = a % n
    result = 1
    while a != 0:
        while a % 2 == 0:
            a //= 2
            n_mod8 = n % 8
            if n_mod8 in (3,5):
                result = -result
        a, n = n, a
        if a % 4 == 3 and n % 4 == 3:
            result = -result
        a = a % n
    return result if n == 1 else 0

# ---------------------------
# JSON canonicalization
# ---------------------------

def canonical_json(obj):
    """Chuẩn hóa JSON: sort keys, no extra spaces, NFC normalization. Trả bytes."""
    s = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(',',':'))
    s = unicodedata.normalize('NFC', s)
    return s.encode('utf-8')

# ---------------------------
# Key generation (Rabin)
# ---------------------------

def rabin_keygen(bits=2048):
    """
    Sinh khóa Rabin:
    - p, q là Blum primes (p ≡ q ≡ 3 mod 4)
    - n = p*q
    Trả dict với p,q,n ở dạng hex string.
    """
    p = gen_blum_prime(bits//2)
    q = gen_blum_prime(bits//2)
    while q == p:
        q = gen_blum_prime(bits//2)
    n = p * q
    return {'p': format(p, 'x'), 'q': format(q, 'x'), 'n': format(n, 'x')}

# ---------------------------
# Chữ ký Rabin (FDH-style)
# ---------------------------

def hash_to_int_fdh(message_bytes, salt_bytes, ctr, n):
    """FDH-style hash -> int mod n, có salt và ctr để rejection sampling."""
    h = hashlib.sha256()
    h.update(b'||')
    # ID đã nằm trong message_bytes, và message_bytes đã được
    # chuẩn hóa NFC bởi canonical_json.
    # Không cần hash ID riêng nữa.
    h.update(message_bytes)
    h.update(b'||')
    h.update(salt_bytes)
    h.update(b'||')
    h.update(str(ctr).encode('ascii'))
    digest = h.digest()
    return int.from_bytes(digest, 'big') % n

def sqrt_mod_p_for_blum(y, p):
    """Tính căn bậc hai mod p khi p ≡ 3 (mod 4): y^{(p+1)/4} mod p"""
    return pow(y, (p+1)//4, p)

def canonical_root_of_y(y, p, q):
    """
    Tạo 4 nghiệm bằng CRT từ sqrt mod p và mod q, rồi chọn một nghiệm canonical (ví dụ nhỏ nhất).
    Việc chọn canonical giúp chữ ký có tính duy nhất để lưu.
    """
    rp = sqrt_mod_p_for_blum(y % p, p)
    rq = sqrt_mod_p_for_blum(y % q, q)
    n = p * q
    roots = []
    for ap in (rp, (-rp) % p):
        for aq in (rq, (-rq) % q):
            x = crt_combine(ap, aq, p, q)
            roots.append(x % n)
    roots = sorted(set(roots))
    return roots[0]

def rabin_sign_ballot(ballot_obj, priv_hex,  salt_len=16):
    """
    Ký ballot_obj bằng Rabin FDH:
    - Đầu vào priv_hex: dict {'p','q','n'} (hex strings)
    - Trả signature dict: {'s':hex, 'salt':hex, 'ctr':int,}
    """
    p = int(priv_hex['p'], 16); q = int(priv_hex['q'], 16); n = int(priv_hex['n'], 16)
    message_bytes = canonical_json(ballot_obj)
    salt = secrets.token_bytes(salt_len)
    ctr = 0
    while True:
        y = hash_to_int_fdh(message_bytes, salt, ctr, n)
        if y != 0 and jacobi(y, p) == 1 and jacobi(y, q) == 1:
            break
        ctr += 1
        if ctr > 10000:
            raise RuntimeError("Quá nhiều vòng thử trong FDH sampling")
    s = canonical_root_of_y(y, p, q)
    return {'s': format(s, 'x'), 'salt': salt.hex(), 'ctr': ctr,}

def rabin_verify_ballot(ballot_obj, sig, pub_hex):
    """Xác minh chữ ký Rabin: kiểm tra s^2 mod n == y (tái tạo y bằng FDH)."""
    n = int(pub_hex['n'], 16)
    s = int(sig['s'], 16)
    salt = bytes.fromhex(sig['salt'])
    ctr = int(sig['ctr'])
    y = hash_to_int_fdh(canonical_json(ballot_obj), salt, ctr, n)
    lhs = pow(s, 2, n)
    return lhs == y

def rabin_verify_bytes(message_bytes, sig, pub_hex):
    """
    Xác minh chữ ký Rabin (sửa lỗi) bằng cách dùng message_bytes đã giải mã,
    thay vì canonicalize lại object.
    """
    n = int(pub_hex['n'], 16)
    s = int(sig['s'], 16)
    salt = bytes.fromhex(sig['salt'])
    ctr = int(sig['ctr'])
    
    # Tái tạo y bằng FDH từ các byte *chính xác* đã được ký
    y = hash_to_int_fdh(message_bytes, salt, ctr, n)
    
    lhs = pow(s, 2, n)
    return lhs == y
# ---------------------------
# Mã hóa/Giải mã Rabin (chỉ dùng cho plaintext ngắn)
# ---------------------------

PAD_MARKER = b'##RABINPAD##'  # marker để chọn nghiệm đúng khi giải mã

def rabin_encrypt_bytes(m_bytes, pub_hex):
    """
    Mã hóa bytes m_bytes bằng Rabin (chỉ dành cho m_int < n).
    Padded = salt(16) || m_bytes || PAD_MARKER
    Trả {'c':hex, 'pad_len':int}
    """
    n = int(pub_hex['n'], 16)
    salt = secrets.token_bytes(16)
    padded = salt + m_bytes + PAD_MARKER
    m_int = int.from_bytes(padded, 'big')
    if m_int >= n:
        raise ValueError("Thông điệp quá dài so với modulus n")
    c = pow(m_int, 2, n)
    return {'c': format(c, 'x'), 'pad_len': len(padded)}

def rabin_decrypt_bytes(cipher_obj, priv_hex):
    """
    Giải mã cipher_obj (dict) bằng priv_hex; thử 4 nghiệm và chọn candidate có PAD_MARKER.
    Trả bytes gốc (m_bytes).
    """
    p = int(priv_hex['p'], 16); q = int(priv_hex['q'], 16); n = int(priv_hex['n'], 16)
    c = int(cipher_obj['c'], 16)
    rp = pow(c % p, (p+1)//4, p)
    rq = pow(c % q, (q+1)//4, q)
    candidates = []
    for ap in (rp, (-rp) % p):
        for aq in (rq, (-rq) % q):
            x = crt_combine(ap, aq, p, q)
            candidates.append(x % n)
    pad_len = int(cipher_obj['pad_len'])
    for cand in candidates:
        b = cand.to_bytes((cand.bit_length()+7)//8 or 1, 'big')
        if len(b) < pad_len:
            b = (b'\x00' * (pad_len - len(b))) + b
        if b.endswith(PAD_MARKER):
            content = b[:-len(PAD_MARKER)]
            # strip salt (16 bytes)
            if len(content) >= 16:
                orig = content[16:]
            else:
                orig = b''
            return orig
    raise ValueError("Không tìm thấy nghiệm phù hợp chứa PAD_MARKER (decrypt failed)")

# ---------------------------
# Hàm tiện ích I/O
# ---------------------------

def save_json(obj, path):
    """Lưu obj ra file JSON (utf-8)."""
    path = Path(path)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(obj, f, ensure_ascii=False, indent=2, sort_keys=True)

def load_json(path):
    """Đọc file JSON ra object Python."""
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)
