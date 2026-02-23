"""
config.py
File cấu hình cho project Rabin Voting (Cloud version).
Đã dọn dẹp các thư mục local không cần thiết, tối ưu cho Supabase.
"""

import os
from pathlib import Path

# --------------------
# CẤU HÌNH DATABASE (SUPABASE)
# --------------------
DB_URI = "postgresql://postgres:Megumikatou2309@db.frhrlvtyjjuyyajeupel.supabase.co:5432/postgres"

# --------------------
# CẤU HÌNH ĐƯỜNG DẪN LOCAL (Chỉ giữ lại những gì GUI yêu cầu)
# --------------------
PROJECT_ROOT = Path(__file__).resolve().parent

# gui_user.py yêu cầu thư mục này để lưu Private Key của chủ phòng (phục vụ kiểm phiếu)
KEYS_AUTHORITY_DIR = PROJECT_ROOT / "keys" / "authority"

def ensure_structure():
    """Tạo thư mục lưu private key cho chủ phòng nếu chưa có."""
    KEYS_AUTHORITY_DIR.mkdir(parents=True, exist_ok=True)

# Khởi tạo thư mục khi import
try:
    ensure_structure()
except Exception:
    pass