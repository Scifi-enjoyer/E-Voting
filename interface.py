"""
gui_user.py
Giao diện User Đa Năng (Voter + Authority).
"""
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, simpledialog
import sys, os, time, json, csv
from pathlib import Path

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
        
        for F in (LoginFrame, MainAppFrame,AdminAppFrame):
            page_name = F.__name__
            frame = F(parent=self.container, controller=self)
            self.frames[page_name] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame("LoginFrame")

    def show_frame(self, page_name):
        frame = self.frames[page_name]
        frame.tkraise()
        # Kích hoạt on_show() cho cả User và Admin
        if (page_name == "MainAppFrame" or page_name == "AdminAppFrame") and CURRENT_USER:
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
            
            # --- KIỂM TRA ROLE ĐỂ CHUYỂN HƯỚNG ---
            if CURRENT_USER['role'].upper() == 'ADMIN':
                self.controller.show_frame("AdminAppFrame")
            else:
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
        
        header_frame = tk.Frame(self)
        header_frame.pack(fill="x", padx=10, pady=10)

        self.lbl_header = tk.Label(header_frame, text="Xin chào!", font=("Arial", 12, "bold"), fg="#1976D2")
        self.lbl_header.pack(side=tk.LEFT)

        tk.Button(header_frame, text="🚪 Đăng xuất", bg="#757575", fg="white", 
                  font=("Arial", 9, "bold"), command=self.do_logout).pack(side=tk.RIGHT)

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=5)

        self.tab_vote = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_vote, text="🗳️ Tham gia Bỏ phiếu")
        self.setup_vote_tab()

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
            # Báo cho Database biết user này đã offline
            db.logout_user(CURRENT_USER['id'])
            CURRENT_USER = None
            
        # 1. XÓA BẢNG: Quét sạch danh sách phòng ở cả 2 Tab
        for item in self.tree_elections.get_children():
            self.tree_elections.delete(item)
        for item in self.tree_my_rooms.get_children():
            self.tree_my_rooms.delete(item)
            
        # 2. XÓA LOG & BIẾN TẠM: Reset trắng màn hình log kiểm phiếu
        self.log_text.delete(1.0, tk.END)
        if hasattr(self, 'current_report_data'):
            self.current_report_data = [] # Xóa bộ nhớ đệm của file Excel
            
        # 3. KHÓA NÚT BẤM: Đưa nút Xuất và Mở file về trạng thái tắt
        self.btn_export_excel.config(state=tk.DISABLED)
        self.btn_open_excel.config(state=tk.DISABLED)
        
        # 4. DỌN FORM TẠO PHÒNG: Xóa các chữ lỡ gõ dở ở ô tạo phòng
        self.new_room_entry.delete(0, tk.END)
        self.room_options_entry.delete(0, tk.END)
        self.room_pass_entry.delete(0, tk.END)
        self.vote_type_var.set("free")
        self.toggle_options()
            
        # 5. Chuyển giao diện về lại màn hình Đăng nhập
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

        from tkinter import simpledialog
        tk.Button(self.tab_vote, text="🚪 VÀO PHÒNG BỎ PHIẾU", bg="#4CAF50", fg="white", 
                  font=("Arial", 12, "bold"), command=self.open_room_popup).pack(pady=10)
        self.tree_elections.bind("<Double-1>", lambda event: self.open_room_popup())

    def load_public_elections(self):
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
        
        from tkinter import simpledialog
        real_password = election.get('room_password')
        if real_password:
            entered_pass = simpledialog.askstring("Yêu cầu Mật khẩu", f"Phòng '{election_name}' có mật khẩu.\nVui lòng nhập để vào:", parent=self, show='*')
            if entered_pass is None:
                return
            if entered_pass != real_password:
                messagebox.showerror("Lỗi", "Sai mật khẩu phòng! Bạn không được phép vào.")
                return
        
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
                self.load_public_elections() 
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

        tk.Label(create_frame, text="Mật khẩu phòng (Tùy chọn):").grid(row=3, column=0, sticky="w", pady=5)
        self.room_pass_entry = tk.Entry(create_frame, width=30)
        self.room_pass_entry.grid(row=3, column=1, sticky="w", pady=5)

        tk.Button(create_frame, text="Tạo Phòng", bg="#D32F2F", fg="white", command=self.create_room).grid(row=0, column=2, rowspan=4, padx=15)

        list_frame = tk.LabelFrame(self.tab_manage, text="Phòng do tôi làm Chủ", padx=10, pady=10)
        list_frame.pack(fill="both", expand=True, padx=5, pady=5)

        cols = ("id", "name", "status")
        self.tree_my_rooms = ttk.Treeview(list_frame, columns=cols, show="headings", height=5)
        self.tree_my_rooms.heading("id", text="ID")
        self.tree_my_rooms.heading("name", text="Tên Phòng")
        self.tree_my_rooms.heading("status", text="Trạng thái")
        self.tree_my_rooms.column("id", width=50)
        self.tree_my_rooms.pack(fill="x", pady=5)
        
        # Bắt sự kiện chọn phòng để kiểm tra trạng thái nút mở file
        self.tree_my_rooms.bind("<<TreeviewSelect>>", self.on_room_select)
        
        # --- CỤM 3 NÚT CHỨC NĂNG ---
        btn_action_frame = tk.Frame(list_frame)
        btn_action_frame.pack(pady=5)
        
        self.btn_check_votes = tk.Button(btn_action_frame, text="📥 KIỂM PHIẾU", bg="#388E3C", fg="white", font=("Arial", 10, "bold"), command=self.process_my_room)
        self.btn_check_votes.pack(side=tk.LEFT, padx=5)
        
        self.btn_export_excel = tk.Button(btn_action_frame, text="📊 XUẤT EXCEL", bg="#FF9800", fg="white", font=("Arial", 10, "bold"), command=self.export_to_excel, state=tk.DISABLED)
        self.btn_export_excel.pack(side=tk.LEFT, padx=5)
        
        self.btn_open_excel = tk.Button(btn_action_frame, text="📂 MỞ FILE", bg="#1976D2", fg="white", font=("Arial", 10, "bold"), command=self.open_excel_file, state=tk.DISABLED)
        self.btn_open_excel.pack(side=tk.LEFT, padx=5)
        
        self.log_text = scrolledtext.ScrolledText(list_frame, height=8)
        self.log_text.pack(fill="both", expand=True)

    def toggle_options(self):
        if self.vote_type_var.get() == "fixed":
            self.room_options_entry.config(state="normal")
        else:
            self.room_options_entry.delete(0, tk.END)
            self.room_options_entry.config(state="disabled")

    def load_my_elections(self):
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
        
        room_password = self.room_pass_entry.get().strip()
        if not room_password:
            room_password = None

        if vote_type == 'fixed' and not options:
            messagebox.showwarning("Lỗi", "Vui lòng nhập các lựa chọn cho phòng!")
            return
        
        self.log_text.insert(tk.END, f"Đang tạo khóa Rabin cho phòng '{name}'...\n")
        self.controller.root.update() 
        
        key = rabin.rabin_keygen(bits=2048)
        
        election_id = db.create_election(name, key['n'], CURRENT_USER['id'], vote_type, options, key, room_password)
        
        if election_id:
            self.log_text.insert(tk.END, f"[OK] Tạo phòng thành công! ID = {election_id}\n")
            if room_password:
                self.log_text.insert(tk.END, f"[🔒] Phòng được bảo vệ bằng mật khẩu.\n")
            self.log_text.insert(tk.END, f"[CLOUD] Khóa Bí Mật đã được mã hóa và đồng bộ lên Server!\n\n")
            
            self.new_room_entry.delete(0, tk.END)
            self.room_options_entry.delete(0, tk.END)
            self.room_pass_entry.delete(0, tk.END)
            
            self.load_my_elections()
            self.load_public_elections()
        else:
            messagebox.showerror("Lỗi", "Không thể tạo phòng trên DB.")

    # --- CÁC HÀM XỬ LÝ LOGIC EXCEL & KIỂM PHIẾU MỚI ---
    
    def on_room_select(self, event):
        """Kích hoạt khi bấm vào 1 phòng trong danh sách"""
        selected = self.tree_my_rooms.selection()
        if not selected:
            return
        election_id = self.tree_my_rooms.item(selected[0])['values'][0]
        
        # Luôn disable nút Xuất Excel khi vừa chọn phòng mới (vì chưa bấm kiểm phiếu)
        self.btn_export_excel.config(state=tk.DISABLED)
        
        # Check xem phòng này đã từng xuất file trên máy chưa
        report_dir = config.PROJECT_ROOT / "reports"
        file_path = report_dir / f"BaoCao_Phong_{election_id}.csv"
        
        if file_path.exists():
            self.btn_open_excel.config(state=tk.NORMAL) # Mở khóa nút Mở file
        else:
            self.btn_open_excel.config(state=tk.DISABLED)

    def process_my_room(self):
        selected = self.tree_my_rooms.selection()
        if not selected:
            messagebox.showwarning("Lỗi", "Chọn 1 phòng để kiểm phiếu!")
            return
            
        election_id = self.tree_my_rooms.item(selected[0])['values'][0]
        election_name = self.tree_my_rooms.item(selected[0])['values'][1]
        
        election = db.get_election_by_id(election_id)
        if not election or not election.get('authority_priv'):
            messagebox.showerror("Lỗi", "Không tìm thấy Khóa Bí Mật của phòng này trên Server!")
            return
            
        auth_priv = json.loads(election['authority_priv'])
        all_votes = db.get_all_votes_by_election(election_id)
        
        self.log_text.insert(tk.END, f"\n========== KẾT QUẢ KIỂM PHIẾU: {election_name} ==========\n")
        
        valid_count = 0
        invalid_count = 0
        tally_results = {}
        
        # Biến lưu trữ dữ liệu chi tiết để xuất ra Excel sau đó
        self.current_report_data = []
        self.current_election_id = election_id
        self.current_election_name = election_name
        
        for vote in all_votes:
            try:
                cipher = json.loads(vote['cipher_ballot'])
                
                if vote['status'] == 'PENDING':
                    sig = json.loads(vote['voter_sig'])
                    pub_n = {'n': vote['voter_pub_n']}
                    
                    ballot_bytes = rabin.rabin_decrypt_bytes(cipher, auth_priv)
                    is_valid = rabin.rabin_verify_bytes(ballot_bytes, sig, pub_n)
                    
                    new_status = 'VALID' if is_valid else 'INVALID'
                    db.update_vote_status(vote['id'], new_status)
                    vote['status'] = new_status
                
                if vote['status'] == 'VALID':
                    valid_count += 1
                    ballot_bytes = rabin.rabin_decrypt_bytes(cipher, auth_priv)
                    ballot_content = json.loads(ballot_bytes.decode('utf-8'))
                    choice = ballot_content.get('choices', 'Không rõ')
                    
                    if choice in tally_results:
                        tally_results[choice] += 1
                    else:
                        tally_results[choice] = 1
                        
                    # Lưu dữ liệu hợp lệ vào biến báo cáo (Không in ra log)
                    self.current_report_data.append([election_id, election_name, vote['id'], "HỢP LỆ", choice, ""])
                        
                elif vote['status'] == 'INVALID':
                    invalid_count += 1
                    # Lưu dữ liệu hỏng vào biến báo cáo
                    self.current_report_data.append([election_id, election_name, vote['id'], "KHÔNG HỢP LỆ", "N/A", "Sai chữ ký hoặc lỗi dữ liệu"])
                    
            except Exception as e:
                if vote['status'] == 'PENDING':
                    db.update_vote_status(vote['id'], 'INVALID')
                invalid_count += 1
                self.current_report_data.append([election_id, election_name, vote['id'], "LỖI KỸ THUẬT", "N/A", str(e)])
                
        self.log_text.insert(tk.END, f"Tổng số phiếu HỢP LỆ: {valid_count}\n")
        self.log_text.insert(tk.END, f"Tổng số phiếu KHÔNG HỢP LỆ: {invalid_count}\n\n")
        self.log_text.insert(tk.END, f"🏆 KẾT QUẢ BẦU CỬ CHUNG CUỘC:\n")
        if not tally_results:
            self.log_text.insert(tk.END, f"Chưa có phiếu hợp lệ nào.\n")
        else:
            for choice, count in tally_results.items():
                self.log_text.insert(tk.END, f"   ➤ {choice}: {count} phiếu\n")
        
        self.log_text.insert(tk.END, f"--------------------------------------------------\n")
        self.log_text.insert(tk.END, f"Đã có dữ liệu chi tiết của từng lá phiếu.\nVui lòng bấm '📊 XUẤT EXCEL' để lưu và xem chi tiết.\n")
        self.log_text.insert(tk.END, f"==================================================\n\n")
        self.log_text.see(tk.END)
        
        # Kiểm phiếu xong -> Cho phép bấm nút Xuất Excel
        self.btn_export_excel.config(state=tk.NORMAL)

    def export_to_excel(self):
        if not hasattr(self, 'current_report_data') or not self.current_report_data:
            messagebox.showwarning("Lỗi", "Không có dữ liệu để xuất! Vui lòng kiểm phiếu trước.")
            return
            
        election_id = self.current_election_id
        
        # Tạo folder reports để lưu trữ cho gọn gàng
        report_dir = config.PROJECT_ROOT / "reports"
        report_dir.mkdir(exist_ok=True)
        file_path = report_dir / f"BaoCao_Phong_{election_id}.csv"
        
        try:
            # Dùng chuẩn utf-8-sig để Excel nhận diện chuẩn tiếng Việt
            with open(file_path, 'w', newline='', encoding='utf-8-sig') as f:
                writer = csv.writer(f)
                writer.writerow(["Mã Phòng", "Tên Phòng", "Mã Lá Phiếu (Vote ID)", "Trạng Thái", "Lựa Chọn (Nếu Hợp Lệ)", "Ghi Chú"])
                for row in self.current_report_data:
                    writer.writerow(row)
                    
            self.log_text.insert(tk.END, f"[THÀNH CÔNG] Đã xuất file Audit Log tại: {file_path.name}\n\n")
            self.log_text.see(tk.END)
            
            # Xuất file thành công -> Cho phép bấm nút Mở file
            self.btn_open_excel.config(state=tk.NORMAL)
            messagebox.showinfo("Thành công", f"Xuất báo cáo thành công!\nBạn có thể bấm Mở File để xem ngay.")
            
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể tạo file báo cáo: {e}")

    def open_excel_file(self):
        selected = self.tree_my_rooms.selection()
        if not selected:
            return
        election_id = self.tree_my_rooms.item(selected[0])['values'][0]
        
        report_dir = config.PROJECT_ROOT / "reports"
        file_path = report_dir / f"BaoCao_Phong_{election_id}.csv"
        
        if file_path.exists():
            try:
                os.startfile(file_path) # Lệnh này sẽ mở file bằng phần mềm Excel mặc định trên Windows
            except AttributeError:
                import subprocess
                subprocess.call(('open', file_path)) # Dành cho MacOS nếu có lỡ chạy
        else:
            messagebox.showerror("Lỗi", "Không tìm thấy file báo cáo!")

class AdminAppFrame(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.auto_refresh_id = None
        
        # Header
        header_frame = tk.Frame(self)
        header_frame.pack(fill="x", padx=10, pady=10)

        self.lbl_header = tk.Label(header_frame, text="⚙️ SUPABASE ADMIN DASHBOARD", font=("Arial", 14, "bold"), fg="#D32F2F")
        self.lbl_header.pack(side=tk.LEFT)

        tk.Button(header_frame, text="🚪 Đăng xuất", bg="#757575", fg="white", 
                  font=("Arial", 9, "bold"), command=self.do_logout).pack(side=tk.RIGHT)
        tk.Button(header_frame, text="🔄 Làm mới thủ công", bg="#1976D2", fg="white", 
                  font=("Arial", 9), command=self.load_all_data).pack(side=tk.RIGHT, padx=10)

        # Tabs
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=5)

        # TAB 1: USERS
        self.tab_users = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_users, text="👥 Bảng Users")
        self.tree_users = ttk.Treeview(self.tab_users, columns=("id", "username", "name", "role", "online"), show="headings")
        self.tree_users.heading("id", text="ID"); self.tree_users.column("id", width=50, anchor="center")
        self.tree_users.heading("username", text="Username")
        self.tree_users.heading("name", text="Full Name")
        self.tree_users.heading("role", text="Role"); self.tree_users.column("role", width=100, anchor="center")
        self.tree_users.heading("online", text="Online"); self.tree_users.column("online", width=80, anchor="center")
        self.tree_users.pack(fill="both", expand=True, padx=5, pady=5)

        # TAB 2: ELECTIONS
        self.tab_elections = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_elections, text="🗳️ Bảng Elections")
        self.tree_elections = ttk.Treeview(self.tab_elections, columns=("id", "name", "creator", "type", "active", "pass"), show="headings")
        self.tree_elections.heading("id", text="ID"); self.tree_elections.column("id", width=50, anchor="center")
        self.tree_elections.heading("name", text="Tên Phòng")
        self.tree_elections.heading("creator", text="ID Người tạo"); self.tree_elections.column("creator", width=100, anchor="center")
        self.tree_elections.heading("type", text="Loại"); self.tree_elections.column("type", width=80, anchor="center")
        self.tree_elections.heading("active", text="Mở/Đóng"); self.tree_elections.column("active", width=80, anchor="center")
        self.tree_elections.heading("pass", text="Mật khẩu"); self.tree_elections.column("pass", width=100, anchor="center")
        self.tree_elections.pack(fill="both", expand=True, padx=5, pady=5)

        # TAB 3: VOTES
        self.tab_votes = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_votes, text="📨 Bảng Votes")
        self.tree_votes = ttk.Treeview(self.tab_votes, columns=("id", "user_id", "election_id", "status"), show="headings")
        self.tree_votes.heading("id", text="Vote ID"); self.tree_votes.column("id", width=80, anchor="center")
        self.tree_votes.heading("user_id", text="User ID"); self.tree_votes.column("user_id", width=100, anchor="center")
        self.tree_votes.heading("election_id", text="Election ID"); self.tree_votes.column("election_id", width=100, anchor="center")
        self.tree_votes.heading("status", text="Trạng thái xử lý"); self.tree_votes.column("status", width=150, anchor="center")
        self.tree_votes.pack(fill="both", expand=True, padx=5, pady=5)

    def on_show(self):
        self.lbl_header.config(text=f"⚙️ ADMIN DASHBOARD | Hello: {CURRENT_USER['username']}")
        self.load_all_data()
        self.auto_refresh() # Bắt đầu vòng lặp realtime

    def load_all_data(self):
        # Clear bảng
        for tree in [self.tree_users, self.tree_elections, self.tree_votes]:
            for item in tree.get_children():
                tree.delete(item)
                
        # Load Users
        for u in db.get_all_users_admin():
            self.tree_users.insert("", "end", values=(u['id'], u['username'], u['full_name'], u['role'], "🟢 Yes" if u['is_online'] else "🔴 No"))
            
        # Load Elections
        for e in db.get_all_elections_admin():
            has_pass = "Có" if e['room_password'] else "Không"
            self.tree_elections.insert("", "end", values=(e['id'], e['name'], e['creator_id'], e['vote_type'], "Mở" if e['is_active'] else "Đóng", has_pass))
            
        # Load Votes
        for v in db.get_all_votes_admin():
            self.tree_votes.insert("", "end", values=(v['id'], v['user_id'], v['election_id'], v['status']))

    def auto_refresh(self):
        """Tự động cập nhật dữ liệu mỗi 5 giây (Realtime)"""
        # Chỉ cập nhật nếu Admin đang đăng nhập và ở màn hình này
        if CURRENT_USER and CURRENT_USER['role'].upper() == 'ADMIN':
            self.load_all_data()
            self.auto_refresh_id = self.after(5000, self.auto_refresh)

    def do_logout(self):
        global CURRENT_USER
        if self.auto_refresh_id:
            self.after_cancel(self.auto_refresh_id) # Tắt vòng lặp realtime
        if CURRENT_USER:
            db.logout_user(CURRENT_USER['id'])
            CURRENT_USER = None
        for tree in [self.tree_users, self.tree_elections, self.tree_votes]:
            for item in tree.get_children():
                tree.delete(item)
        self.controller.show_frame("LoginFrame")

if __name__ == "__main__":
    root = tk.Tk()
    app = UserApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()