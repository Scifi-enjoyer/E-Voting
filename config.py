"""
config.py
File cấu hình cho project Rabin Voting (Cloud version).
Đã tối ưu cho cấu trúc thư mục phẳng.
"""
from pathlib import Path

# Xác định thư mục gốc (Dùng để tạo folder reports xuất Excel)
PROJECT_ROOT = Path(__file__).resolve().parent

# Chuỗi kết nối Database Supabase
DB_URI = "postgresql://postgres:Megumikatou2309@db.frhrlvtyjjuyyajeupel.supabase.co:5432/postgres"