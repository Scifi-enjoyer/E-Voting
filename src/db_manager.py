"""
src/db_manager.py
Cập nhật cho mô hình Platform (User có thể tạo và tham gia phòng).
"""
import psycopg2
from psycopg2.extras import RealDictCursor
import json
import hashlib
import sys, os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import config

def get_connection():
    try:
        conn = psycopg2.connect(config.DB_URI)
        return conn
    except Exception as e:
        print(f"[DB ERROR] Không thể kết nối Supabase: {e}")
        return None

# --- AUTH ---
def login_user(username, password):
    conn = get_connection()
    if not conn: return None
    try:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        pw_hash = hashlib.sha256(password.encode()).hexdigest()
        cursor.execute("SELECT * FROM users WHERE username = %s AND password_hash = %s", (username, pw_hash))
        user = cursor.fetchone()
        if user:
            with conn.cursor() as up_cur:
                up_cur.execute("UPDATE users SET is_online = TRUE WHERE id = %s", (user['id'],))
            conn.commit()
        return user
    finally:
        conn.close()

def register_user(username, password, full_name, role='VOTER'):
    conn = get_connection()
    if not conn: return False
    try:
        cursor = conn.cursor()
        pw_hash = hashlib.sha256(password.encode()).hexdigest()
        cursor.execute("INSERT INTO users (username, password_hash, full_name, role) VALUES (%s, %s, %s, %s)",
                       (username, pw_hash, full_name, role))
        conn.commit()
        return True
    except:
        return False
    finally:
        conn.close()

def logout_user(user_id):
    conn = get_connection()
    if conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE users SET is_online = FALSE WHERE id = %s", (user_id,))
        conn.commit()
        conn.close()

# --- ELECTIONS (PHÒNG BỎ PHIẾU) ---
def get_all_active_elections():
    """Lấy TẤT CẢ các phòng đang mở để user chọn"""
    conn = get_connection()
    if not conn: return []
    try:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        # Join với bảng users để lấy tên người tạo
        cursor.execute("""
            SELECT e.*, u.full_name as creator_name 
            FROM elections e 
            LEFT JOIN users u ON e.creator_id = u.id 
            WHERE e.is_active = TRUE 
            ORDER BY e.created_at DESC
        """)
        return cursor.fetchall()
    finally:
        conn.close()

def get_my_elections(user_id):
    """Lấy các phòng do CHÍNH USER NÀY tạo"""
    conn = get_connection()
    if not conn: return []
    try:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT * FROM elections WHERE creator_id = %s ORDER BY created_at DESC", (user_id,))
        return cursor.fetchall()
    finally:
        conn.close()

def create_election(name, authority_pub_n, creator_id, vote_type='free', options=None, authority_priv=None, room_password=None):
    """Tạo phòng bỏ phiếu mới lưu cả luật chơi, Khóa và Mật khẩu lên Cloud"""
    conn = get_connection()
    if not conn: return None
    try:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            INSERT INTO elections (name, authority_pub_n, creator_id, is_active, vote_type, options, authority_priv, room_password) 
            VALUES (%s, %s, %s, TRUE, %s, %s, %s, %s) RETURNING id
        """, (name, authority_pub_n, creator_id, vote_type, options, json.dumps(authority_priv), room_password))
        new_id = cursor.fetchone()['id']
        conn.commit()
        return new_id
    except Exception as e:
        print(f"[ERROR] Create election: {e}")
        return None
    finally:
        conn.close()

def get_election_by_id(election_id):
    conn = get_connection()
    try:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT * FROM elections WHERE id = %s", (election_id,))
        return cursor.fetchone()
    finally:
        conn.close()

# --- VOTES ---
def check_if_voted(user_id, election_id):
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM votes WHERE user_id = %s AND election_id = %s", (user_id, election_id))
        return cursor.fetchone() is not None
    finally:
        conn.close()

def submit_vote(user_id, election_id, cipher_ballot, voter_pub_n, voter_sig):
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO votes (user_id, election_id, cipher_ballot, voter_pub_n, voter_sig, status)
            VALUES (%s, %s, %s, %s, %s, 'PENDING')
        """, (user_id, election_id, json.dumps(cipher_ballot), voter_pub_n, json.dumps(voter_sig)))
        conn.commit()
        return True
    except: return False
    finally: conn.close()

def get_pending_votes(election_id):
    conn = get_connection()
    try:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT * FROM votes WHERE election_id = %s AND status = 'PENDING'", (election_id,))
        return cursor.fetchall()
    finally: conn.close()

def update_vote_status(vote_id, status):
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("UPDATE votes SET status = %s WHERE id = %s", (status, vote_id))
        conn.commit()
    finally: conn.close()

# --- ADMIN STATS ---
def get_admin_stats():
    conn = get_connection()
    if not conn: return {}
    try:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT COUNT(*) as c FROM users")
        total_users = cursor.fetchone()['c']
        cursor.execute("SELECT COUNT(*) as c FROM users WHERE is_online = TRUE")
        online_users = cursor.fetchone()['c']
        cursor.execute("SELECT COUNT(*) as c FROM elections")
        total_elections = cursor.fetchone()['c']
        cursor.execute("SELECT COUNT(*) as c FROM votes")
        total_votes = cursor.fetchone()['c']
        return {
            "total_users": total_users, "online_users": online_users,
            "total_elections": total_elections, "total_votes": total_votes
        }
    finally: conn.close()