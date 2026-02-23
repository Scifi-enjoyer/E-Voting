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
        if db.register_user(u, p, u):
            messagebox.showinfo("OK", "Đăng ký thành công! Hãy đăng nhập.")
        else:
            messagebox.showerror("Lỗi", "Tài khoản đã tồn tại.")


class MainAppFrame(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        
        # Bọc header và nút đăng xuất vào chung 1 Frame nằm ngang cho đẹp
        header_frame = tk.Frame(self)
        header_frame.pack(fill="x", padx=10, pady=10)

        self.lbl_header = tk.Label(header_frame, text="Xin chào!", font=("Arial", 12, "bold"), fg="#1976D2")
        self.lbl_header.pack(side=tk.LEFT)

        # Nút Đăng xuất nằm góc phải
        tk.Button(header_frame, text="🚪 Đăng xuất", bg="#757575", fg="white", 
                  font=("Arial", 9, "bold"), command=self.do_logout).pack(side=tk.RIGHT)

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
    def do_logout(self):
        global CURRENT_USER
        if CURRENT_USER:
            # 1. Gọi DB để set is_online = FALSE
            db.logout_user(CURRENT_USER['id'])
            # 2. Xóa biến phiên làm việc hiện tại
            CURRENT_USER = None
            
        # 3. Xóa sạch dữ liệu trên các bảng để người sau đăng nhập không nhìn thấy data của người trước
        for item in self.tree_elections.get_children():
            self.tree_elections.delete(item)
        for item in self.tree_my_rooms.get_children():
            self.tree_my_rooms.delete(item)
            
        # 4. Chuyển giao diện về lại màn hình Đăng nhập
        self.controller.show_frame("LoginFrame")

    # ================= TAB 1: ĐI VOTE =================
    def setup_vote_tab(self):
        top_frame = tk.Frame(self.tab_vote)
        top_frame.pack(fill="x", pady=5)
        tk.Button(top_frame, text="🔄 Làm mới danh sách", command=self.load_public_elections).pack(side=tk.LEFT, padx=5)

        columns = ("id", "name", "creator")
        self.tree_elections = ttk.Treeview(self.tab_vote, columns=columns, show="headings", height=12)
        self.tree_elections.heading("id", text="ID")
        self.tree_elections.heading("name", text="Tên Cuộc Bầu Cử")
        self.tree_elections.heading("creator", text="Người Tạo")
        self.tree_elections.column("id", width=50)
        self.tree_elections.pack(fill="x", padx=10, pady=10)

        # Nút Vào phòng chuyên nghiệp, có thể double-click thẳng vào bảng
        tk.Button(self.tab_vote, text="🚪 VÀO PHÒNG BỎ PHIẾU", bg="#4CAF50", fg="white", 
                  font=("Arial", 12, "bold"), command=self.open_room_popup).pack(pady=10)
        self.tree_elections.bind("<Double-1>", lambda event: self.open_room_popup())

    def load_public_elections(self):
        """Hàm load danh sách phòng bầu cử (đã được khôi phục)"""
        for item in self.tree_elections.get_children():
            self.tree_elections.delete(item)
        elections = db.get_all_active_elections()
        for e in elections:
            self.tree_elections.insert("", "end", values=(e['id'], e['name'], e['creator_name']))

    def open_room_popup(self):
        selected = self.tree_elections.selection()
        if not selected:
            messagebox.showwarning("Lỗi", "Vui lòng chọn 1 phòng từ danh sách để vào!")
            return
            
        election_id = self.tree_elections.item(selected[0])['values'][0]
        election_name = self.tree_elections.item(selected[0])['values'][1]
        host_name = self.tree_elections.item(selected[0])['values'][2]
        
        if db.check_if_voted(CURRENT_USER['id'], election_id):
            messagebox.showerror("Lỗi", "Bạn đã bỏ phiếu trong phòng này rồi. Mỗi người chỉ được 1 phiếu!")
            return

        election = db.get_election_by_id(election_id)
        
        popup = tk.Toplevel(self)
        popup.title(f"Phòng bỏ phiếu: {election_name}")
        popup.geometry("450x350")
        popup.grab_set() 
        
        tk.Label(popup, text=f"🗳️ {election_name}", font=("Arial", 16, "bold"), fg="#1976D2").pack(pady=15)
        tk.Label(popup, text=f"Chủ phòng (Host): {host_name}", font=("Arial", 10, "italic")).pack()
        
        frame_input = tk.Frame(popup)
        frame_input.pack(pady=20, fill="x", padx=30)
        
        choice_var = tk.StringVar()
        
        if election.get('vote_type') == 'fixed':
            tk.Label(frame_input, text="Vui lòng chọn 1 trong các lựa chọn sau:", font=("Arial", 11)).pack(anchor="w", pady=5)
            # Thêm check an toàn nếu options bị rỗng
            options_str = election.get('options', '')
            if options_str:
                options_list = [opt.strip() for opt in options_str.split(',')]
                for opt in options_list:
                    tk.Radiobutton(frame_input, text=opt, variable=choice_var, value=opt, font=("Arial", 11)).pack(anchor="w", pady=3)
        else:
            tk.Label(frame_input, text="Nhập nội dung/lựa chọn bỏ phiếu của bạn:", font=("Arial", 11)).pack(anchor="w", pady=5)
            entry = tk.Entry(frame_input, textvariable=choice_var, width=40, font=("Arial", 11))
            entry.pack(pady=5)
            
        def submit_popup_vote():
            choice = choice_var.get().strip()
            if not choice:
                messagebox.showwarning("Cảnh báo", "Vui lòng đưa ra lựa chọn trước khi chốt phiếu!", parent=popup)
                return
            
            auth_pub = {'n': election['authority_pub_n']}
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
                messagebox.showinfo("Thành công", "Chốt phiếu thành công! Dữ liệu đã được mã hóa an toàn.", parent=popup)
                popup.destroy() 
                self.load_public_elections() # Tải lại bảng sau khi vote
            else:
                messagebox.showerror("Lỗi", "Có lỗi xảy ra khi gửi phiếu tới Database.", parent=popup)
                
        tk.Button(popup, text="🚀 CHỐT PHIẾU", bg="#D32F2F", fg="white", 
                  font=("Arial", 12, "bold"), command=submit_popup_vote).pack(pady=10)


    # ================= TAB 2: QUẢN LÝ PHÒNG =================
    def setup_manage_tab(self):
        create_frame = tk.LabelFrame(self.tab_manage, text="Tạo phòng bầu cử mới", padx=10, pady=10)
        create_frame.pack(fill="x", padx=5, pady=5)
        
        tk.Label(create_frame, text="Tên phòng:").grid(row=0, column=0, sticky="w", pady=5)
        self.new_room_entry = tk.Entry(create_frame, width=30)
        self.new_room_entry.grid(row=0, column=1, sticky="w", pady=5)

        self.vote_type_var = tk.StringVar(value="free")
        tk.Radiobutton(create_frame, text="Bỏ phiếu Tự do", variable=self.vote_type_var, value="free", command=self.toggle_options).grid(row=1, column=0, sticky="w")
        tk.Radiobutton(create_frame, text="Lựa chọn Có sẵn", variable=self.vote_type_var, value="fixed", command=self.toggle_options).grid(row=1, column=1, sticky="w")

        tk.Label(create_frame, text="Các lựa chọn (cách nhau dấu phẩy):").grid(row=2, column=0, sticky="w", pady=5)
        self.room_options_entry = tk.Entry(create_frame, width=30, state="disabled")
        self.room_options_entry.grid(row=2, column=1, sticky="w", pady=5)

        tk.Button(create_frame, text="Tạo Phòng", bg="#D32F2F", fg="white", command=self.create_room).grid(row=0, column=2, rowspan=3, padx=15)

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

    def toggle_options(self):
        if self.vote_type_var.get() == "fixed":
            self.room_options_entry.config(state="normal")
        else:
            self.room_options_entry.delete(0, tk.END)
            self.room_options_entry.config(state="disabled")

    def load_my_elections(self):
        """Hàm load danh sách phòng của tôi (đã được khôi phục)"""
        for item in self.tree_my_rooms.get_children():
            self.tree_my_rooms.delete(item)
        my_rooms = db.get_my_elections(CURRENT_USER['id'])
        for r in my_rooms:
            status = "Đang mở" if r['is_active'] else "Đã đóng"
            self.tree_my_rooms.insert("", "end", values=(r['id'], r['name'], status))

    def create_room(self):
        name = self.new_room_entry.get().strip()
        if not name: return
        
        vote_type = self.vote_type_var.get()
        options = self.room_options_entry.get().strip() if vote_type == 'fixed' else None

        if vote_type == 'fixed' and not options:
            messagebox.showwarning("Lỗi", "Vui lòng nhập các lựa chọn cho phòng!")
            return
        
        self.log_text.insert(tk.END, f"Đang tạo khóa Rabin cho phòng '{name}'...\n")
        self.controller.root.update() 
        
        key = rabin.rabin_keygen(bits=2048)
        
        election_id = db.create_election(name, key['n'], CURRENT_USER['id'], vote_type, options)
        
        if election_id:
            priv_path = config.KEYS_AUTHORITY_DIR / f"priv_election_{election_id}.json"
            rabin.save_json(key, priv_path)
            
            self.log_text.insert(tk.END, f"[OK] Tạo phòng thành công! ID = {election_id}\n")
            self.log_text.insert(tk.END, f"[BẢO MẬT] Đã lưu Private Key tại: {priv_path.name}\n\n")
            self.new_room_entry.delete(0, tk.END)
            self.room_options_entry.delete(0, tk.END)
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
                
                ballot_bytes = rabin.rabin_decrypt_bytes(cipher, auth_priv)
                ballot_content = json.loads(ballot_bytes.decode('utf-8'))
                
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