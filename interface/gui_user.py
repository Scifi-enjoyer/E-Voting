"""
gui_user.py
Giao diện User Đa Năng (Voter + Authority).
"""
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import sys, os, time, json
from pathlib import Path

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(project_root)

import config
import src.db_manager as db
import src.utils_rabin as rabin

CURRENT_USER = None

class UserApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Nền tảng Bỏ phiếu Rabin - User Portal")
        self.root.geometry("800x600")

        self.container = tk.Frame(root)
        self.container.pack(fill="both", expand=True)
        self.frames = {}
        
        for F in (LoginFrame, MainAppFrame):
            page_name = F.__name__
            frame = F(parent=self.container, controller=self)
            self.frames[page_name] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame("LoginFrame")

    def show_frame(self, page_name):
        frame = self.frames[page_name]
        frame.tkraise()
        if page_name == "MainAppFrame" and CURRENT_USER:
            frame.on_show()

    def on_closing(self):
        if CURRENT_USER:
            db.logout_user(CURRENT_USER['id'])
        self.root.destroy()


class LoginFrame(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        tk.Label(self, text="ĐĂNG NHẬP / ĐĂNG KÝ", font=("Arial", 16, "bold")).pack(pady=40)
        
        tk.Label(self, text="Tên đăng nhập:").pack()
        self.user_entry = tk.Entry(self)
        self.user_entry.pack(pady=5)
        
        tk.Label(self, text="Mật khẩu:").pack()
        self.pass_entry = tk.Entry(self, show="*")
        self.pass_entry.pack(pady=5)
        
        btn_frame = tk.Frame(self)
        btn_frame.pack(pady=20)
        tk.Button(btn_frame, text="Đăng nhập", bg="#1976D2", fg="white", width=12, command=self.do_login).pack(side=tk.LEFT, padx=10)
        tk.Button(btn_frame, text="Đăng ký", bg="#FFA000", fg="white", width=12, command=self.do_register).pack(side=tk.LEFT, padx=10)

    def do_login(self):
        u = self.user_entry.get()
        p = self.pass_entry.get()
        user = db.login_user(u, p)
        if user:
            global CURRENT_USER
            CURRENT_USER = user
            self.controller.show_frame("MainAppFrame")
        else:
            messagebox.showerror("Lỗi", "Sai thông tin đăng nhập!")

    def do_register(self):
        u = self.user_entry.get()
        p = self.pass_entry.get()
        if db.register_user(u, p, f"User {u}"):
            messagebox.showinfo("OK", "Đăng ký thành công! Hãy đăng nhập.")
        else:
            messagebox.showerror("Lỗi", "Tài khoản đã tồn tại.")


class MainAppFrame(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        
        self.lbl_header = tk.Label(self, text="Xin chào!", font=("Arial", 12, "bold"), fg="#1976D2")
        self.lbl_header.pack(pady=10)

        # Tạo Tabs
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=5)

        # Tab 1: Đi Vote
        self.tab_vote = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_vote, text="🗳️ Tham gia Bỏ phiếu")
        self.setup_vote_tab()

        # Tab 2: Tạo Phòng
        self.tab_manage = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_manage, text="👑 Quản lý Phòng của tôi")
        self.setup_manage_tab()

    def on_show(self):
        self.lbl_header.config(text=f"Xin chào: {CURRENT_USER['full_name']} | Role: {CURRENT_USER['role']}")
        self.load_public_elections()
        self.load_my_elections()

    # ================= TAB 1: ĐI VOTE =================
    def setup_vote_tab(self):
        top_frame = tk.Frame(self.tab_vote)
        top_frame.pack(fill="x", pady=5)
        tk.Button(top_frame, text="🔄 Làm mới danh sách", command=self.load_public_elections).pack(side=tk.LEFT, padx=5)

        # Bảng danh sách phòng
        columns = ("id", "name", "creator")
        self.tree_elections = ttk.Treeview(self.tab_vote, columns=columns, show="headings", height=8)
        self.tree_elections.heading("id", text="ID")
        self.tree_elections.heading("name", text="Tên Cuộc Bầu Cử")
        self.tree_elections.heading("creator", text="Người Tạo")
        self.tree_elections.column("id", width=50)
        self.tree_elections.pack(fill="x", padx=5, pady=5)

        vote_frame = tk.LabelFrame(self.tab_vote, text="Bỏ phiếu cho phòng đã chọn", padx=10, pady=10)
        vote_frame.pack(fill="x", padx=5, pady=5)
        
        tk.Label(vote_frame, text="Nhập lựa chọn của bạn:").pack(anchor="w")
        self.choice_entry = tk.Entry(vote_frame, width=50)
        self.choice_entry.pack(anchor="w", pady=5)
        
        tk.Button(vote_frame, text="🚀 GỬI PHIẾU BẦU (MÃ HÓA)", bg="#4CAF50", fg="white", 
                  font=("Arial", 10, "bold"), command=self.cast_vote).pack(anchor="w", pady=5)

    def load_public_elections(self):
        for item in self.tree_elections.get_children():
            self.tree_elections.delete(item)
        elections = db.get_all_active_elections()
        for e in elections:
            self.tree_elections.insert("", "end", values=(e['id'], e['name'], e['creator_name']))

    def cast_vote(self):
        selected = self.tree_elections.selection()
        if not selected:
            messagebox.showwarning("Lỗi", "Vui lòng chọn 1 cuộc bầu cử từ bảng trên!")
            return
        
        choice = self.choice_entry.get().strip()
        if not choice:
            messagebox.showwarning("Lỗi", "Vui lòng nhập lựa chọn!")
            return
            
        election_id = self.tree_elections.item(selected[0])['values'][0]
        
        if db.check_if_voted(CURRENT_USER['id'], election_id):
            messagebox.showerror("Lỗi", "Bạn đã bỏ phiếu trong phòng này rồi!")
            return

        election = db.get_election_by_id(election_id)
        auth_pub = {'n': election['authority_pub_n']}

        # Logic mã hóa Rabin
        voter_key = rabin.rabin_keygen(bits=2048)
        ballot = {
            "election_id": election_id,
            "ballot_id": f"vote-{CURRENT_USER['id']}-{int(time.time())}",
            "choices": choice,
            "timestamp": time.time()
        }
        
        voter_sig = rabin.rabin_sign_ballot(ballot, voter_key)
        ballot_bytes = rabin.canonical_json(ballot)
        cipher_ballot = rabin.rabin_encrypt_bytes(ballot_bytes, auth_pub)

        if db.submit_vote(CURRENT_USER['id'], election_id, cipher_ballot, voter_key['n'], voter_sig):
            messagebox.showinfo("Thành công", "Phiếu đã được mã hóa và gửi lên Server!")
            self.choice_entry.delete(0, tk.END)
        else:
            messagebox.showerror("Lỗi", "Có lỗi xảy ra khi gửi phiếu.")

    # ================= TAB 2: QUẢN LÝ PHÒNG =================
    def setup_manage_tab(self):
        # Frame Tạo phòng
        create_frame = tk.LabelFrame(self.tab_manage, text="Tạo phòng bầu cử mới", padx=10, pady=10)
        create_frame.pack(fill="x", padx=5, pady=5)
        
        tk.Label(create_frame, text="Tên phòng:").pack(side=tk.LEFT)
        self.new_room_entry = tk.Entry(create_frame, width=40)
        self.new_room_entry.pack(side=tk.LEFT, padx=5)
        tk.Button(create_frame, text="Tạo Phòng", bg="#D32F2F", fg="white", command=self.create_room).pack(side=tk.LEFT)

        # Bảng phòng của tôi
        list_frame = tk.LabelFrame(self.tab_manage, text="Phòng do tôi làm Chủ", padx=10, pady=10)
        list_frame.pack(fill="both", expand=True, padx=5, pady=5)

        cols = ("id", "name", "status")
        self.tree_my_rooms = ttk.Treeview(list_frame, columns=cols, show="headings", height=5)
        self.tree_my_rooms.heading("id", text="ID")
        self.tree_my_rooms.heading("name", text="Tên Phòng")
        self.tree_my_rooms.heading("status", text="Trạng thái")
        self.tree_my_rooms.column("id", width=50)
        self.tree_my_rooms.pack(fill="x", pady=5)
        
        tk.Button(list_frame, text="📥 KIỂM PHIẾU PHÒNG ĐÃ CHỌN", bg="#388E3C", fg="white", 
                  font=("Arial", 10, "bold"), command=self.process_my_room).pack(pady=5)
        
        self.log_text = scrolledtext.ScrolledText(list_frame, height=8)
        self.log_text.pack(fill="both", expand=True)

    def load_my_elections(self):
        for item in self.tree_my_rooms.get_children():
            self.tree_my_rooms.delete(item)
        my_rooms = db.get_my_elections(CURRENT_USER['id'])
        for r in my_rooms:
            status = "Đang mở" if r['is_active'] else "Đã đóng"
            self.tree_my_rooms.insert("", "end", values=(r['id'], r['name'], status))

    def create_room(self,root):
        name = self.new_room_entry.get().strip()
        if not name: return
        
        self.log_text.insert(tk.END, f"Đang tạo khóa Rabin cho phòng '{name}'...\n")
        self.root.update()
        
        # 1. Sinh khóa Authority
        key = rabin.rabin_keygen(bits=2048)
        
        # 2. Đẩy Public Key lên DB
        election_id = db.create_election(name, key['n'], CURRENT_USER['id'])
        
        if election_id:
            # 3. Lưu Private Key cục bộ theo ID phòng
            priv_path = config.KEYS_AUTHORITY_DIR / f"priv_election_{election_id}.json"
            rabin.save_json(key, priv_path)
            
            self.log_text.insert(tk.END, f"[OK] Tạo phòng thành công! ID = {election_id}\n")
            self.log_text.insert(tk.END, f"[BẢO MẬT] Đã lưu Private Key tại: {priv_path.name}\n\n")
            self.new_room_entry.delete(0, tk.END)
            self.load_my_elections()
            self.load_public_elections()
        else:
            messagebox.showerror("Lỗi", "Không thể tạo phòng trên DB.")

    def process_my_room(self):
        selected = self.tree_my_rooms.selection()
        if not selected:
            messagebox.showwarning("Lỗi", "Chọn 1 phòng để kiểm phiếu!")
            return
            
        election_id = self.tree_my_rooms.item(selected[0])['values'][0]
        election_name = self.tree_my_rooms.item(selected[0])['values'][1]
        
        # Đọc Private Key cục bộ
        priv_path = config.KEYS_AUTHORITY_DIR / f"priv_election_{election_id}.json"
        if not priv_path.exists():
            messagebox.showerror("Lỗi", f"Không tìm thấy Private Key của phòng này!\n({priv_path.name})\nChỉ máy tính tạo phòng mới có thể kiểm phiếu.")
            return
            
        auth_priv = rabin.load_json(priv_path)
        pending_votes = db.get_pending_votes(election_id)
        
        self.log_text.insert(tk.END, f"--- BẮT ĐẦU KIỂM PHIẾU PHÒNG: {election_name} ---\n")
        self.log_text.insert(tk.END, f"Tìm thấy {len(pending_votes)} phiếu chưa xử lý.\n")
        
        valid_count = 0
        for vote in pending_votes:
            try:
                cipher = json.loads(vote['cipher_ballot'])
                sig = json.loads(vote['voter_sig'])
                pub_n = {'n': vote['voter_pub_n']}
                
                # Giải mã
                ballot_bytes = rabin.rabin_decrypt_bytes(cipher, auth_priv)
                ballot_content = json.loads(ballot_bytes.decode('utf-8'))
                
                # Xác thực
                is_valid = rabin.rabin_verify_bytes(ballot_bytes, sig, pub_n)
                db.update_vote_status(vote['id'], 'VALID' if is_valid else 'INVALID')
                
                if is_valid:
                    valid_count += 1
                    self.log_text.insert(tk.END, f"[Hợp lệ] Phiếu #{vote['id']} -> Bầu cho: {ballot_content['choices']}\n")
                else:
                    self.log_text.insert(tk.END, f"[Cảnh báo] Phiếu #{vote['id']} -> CHỮ KÝ SAI!\n")
            except Exception as e:
                db.update_vote_status(vote['id'], 'INVALID')
                self.log_text.insert(tk.END, f"[Lỗi] Phiếu #{vote['id']} -> Lỗi giải mã: {e}\n")
                
        self.log_text.insert(tk.END, f"-> TỔNG KẾT: {valid_count}/{len(pending_votes)} phiếu hợp lệ.\n\n")
        self.log_text.see(tk.END)

if __name__ == "__main__":
    config.ensure_structure()
    root = tk.Tk()
    app = UserApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()