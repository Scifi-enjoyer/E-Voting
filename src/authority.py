"""
authority.py
Phía kiểm phiếu:
- Sinh khóa Authority (rabin_keygen)
- Nhận file .json của voter (mỗi file == 1 phiếu)
- Giải mã cipher_ballot, lấy ballot, verify voter_sig dùng voter_pub (trong file)
- In kết quả
"""

import json
from pathlib import Path
import sys, os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import config
import src.utils_rabin as rabin

def authority_keygen(bits=2048, out_priv=None, out_pub=None):
    """Sinh khóa Authority và lưu ra file."""
    key = rabin.rabin_keygen(bits=bits)
    priv_path = out_priv or config.get_authority_priv_path()
    pub_path = out_pub or config.get_authority_pub_path()
    rabin.save_json(key, priv_path)
    rabin.save_json({'n': key['n']}, pub_path)
    print(f"[OK] Đã sinh khóa Authority. Private -> {priv_path}, Public -> {pub_path}")

def authority_decrypt_and_verify(auth_priv_file, vote_file):
    """
    Xử lý 1 file vote (do voter tạo):
    - Giải mã, xác thực.
    - Nâng cấp: Lưu kết quả (ballot đã giải mã HOẶC lỗi) ra file mới
    - trong 'votes_approved' / 'votes_not_approved' và xóa file gốc.
    """
    auth_priv = rabin.load_json(auth_priv_file)
    p_vote = Path(vote_file) # Path object của file vote gốc
    
    try:
        package = rabin.load_json(vote_file)
    except Exception as e:
        print(f"[ERROR] File vote {p_vote.name} bị lỗi JSON, không đọc được: {e}")
        # File gốc bị lỗi, không thể xử lý
        ok = False
        ballot = {
            "error": "File JSON không hợp lệ", 
            "details": str(e),
            "original_filename": p_vote.name
        }
        # Sẽ di chuyển file lỗi này đi
        dest_folder = config.NOT_APPROVED_DIR
        dest_path = dest_folder / p_vote.name
        config.NOT_APPROVED_DIR.mkdir(exist_ok=True)
        try:
            p_vote.rename(dest_path)
            print(f"[INFO] Đã di chuyển file JSON lỗi tới: {dest_path}")
        except Exception as move_e:
            print(f"[CRITICAL] Không thể di chuyển file lỗi {p_vote.name}: {move_e}")
        return False # Dừng sớm

    cipher_ballot = package.get('cipher_ballot')
    voter_pub = package.get('voter_pub')
    voter_sig = package.get('voter_sig')

    ok = False  # Mặc định là False
    ballot = {} # Khởi tạo ballot

    try:
        if cipher_ballot is None or voter_pub is None or voter_sig is None:
            ok = False
            ballot = {
                'error': 'Thiếu trường dữ liệu (cipher_ballot, voter_pub, or voter_sig)',
                'package_content': package # Lưu lại nội dung package lỗi
            }
        else:
            # Giải mã ballot
            try:
                ballot_bytes = rabin.rabin_decrypt_bytes(cipher_ballot, auth_priv)
                ballot = json.loads(ballot_bytes.decode('utf-8'))
            except Exception as e:
                ok = False
                ballot = {
                    'error': 'Giải mã thất bại (Decrypt failed)', 
                    'details': str(e),
                    'voter_pub': voter_pub, # Lưu lại pubkey để kiểm tra
                    'voter_sig': voter_sig
                }
                # Dù giải mã thất bại, ta vẫn tiếp tục để lưu file lỗi
                
            # Nếu giải mã thành công (ballot có nội dung)
            if not ballot.get('error'):
                # Verify chữ ký voter
                ok = rabin.rabin_verify_bytes(ballot_bytes, voter_sig, voter_pub)
                
                if not ok:
                    # Giải mã ĐÚNG, nhưng chữ ký SAI
                    ballot['error'] = 'Chữ ký không hợp lệ (Invalid Signature)'

    except Exception as e:
        # Bắt lỗi không lường trước
        print(f"[ERROR] Lỗi nghiêm trọng khi xử lý {p_vote.name}: {e}")
        ok = False
        ballot['error'] = 'Lỗi xử lý không xác định'
        ballot['details'] = str(e)


    # ---- In kết quả (giữ nguyên) ----
    print("=== KẾT QUẢ KIỂM PHIẾU ===")
    print("Vote file:", vote_file)
    print("Ballot ID:", ballot.get('ballot_id', 'N/A - Lỗi'))
    print("Nội dung (hoặc lỗi):", json.dumps(ballot, ensure_ascii=False, indent=2, sort_keys=True))
    print("Chữ ký voter hợp lệ?:", ok)
    
    if ok:
        print("[SUCCESS] Phiếu hợp lệ.")
    else:
        print("[ALERT] Phiếu KHÔNG hợp lệ.")

    # --- PHẦN LƯU KẾT QUẢ VÀ DỌN DẸP (MỚI) ---
    try:
        # Đảm bảo thư mục đích tồn tại
        config.APPROVED_DIR.mkdir(exist_ok=True)
        config.NOT_APPROVED_DIR.mkdir(exist_ok=True)

        dest_folder = config.APPROVED_DIR if ok else config.NOT_APPROVED_DIR
        
        # Chúng ta lưu file KẾT QUẢ (đã giải mã/lỗi), 
        # dùng tên file gốc
        dest_path = dest_folder / p_vote.name
        
        # Ghi đè nếu file kết quả đã tồn tại
        rabin.save_json(ballot, dest_path)
        
        # Xóa file gốc trong thư mục 'votes/'
        p_vote.unlink() 
        
        print(f"[INFO] Đã LƯU KẾT QUẢ vào: {dest_path}")
        print(f"[INFO] Đã XÓA phiếu gốc: {vote_file}")
        
    except Exception as e:
        print(f"[CRITICAL ERROR] KHÔNG THỂ lưu kết quả/xóa file {vote_file}: {e}")
    # --- HẾT PHẦN MỚI ---

    return ok

def authority_verify_all_in_folder(auth_priv_file, folder=None):
    """
    Duyệt tất cả file vote_*.json trong folder và verify từng file.
    In summary cuối cùng.
    """
    folder = Path(folder or config.get_vote_folder())
    files = sorted(folder.glob("vote_*.json"))
    total = len(files)
    valid = 0
    print(f"[INFO] Tìm thấy {total} file trong {folder}")
    for f in files:
        ok = authority_decrypt_and_verify(auth_priv_file, str(f))
        if ok:
            valid += 1
    print(f"[SUMMARY] Valid: {valid} / {total}")
    return valid, total
