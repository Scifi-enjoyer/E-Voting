"""
interface.py
Giao diện User Đa Năng (Voter + Authority).
Đã nâng cấp Flat Design & Tối ưu đa luồng (Multithreading).
"""
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, simpledialog
import sys, os, time, json, csv
from datetime import datetime
import threading # THƯ VIỆN ĐA LUỒNG
from pathlib import Path

import config
import src.db_manager as db
import src.utils_rabin as rabin

CURRENT_USER = None

class UserApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Nền tảng Bỏ phiếu Rabin - Hệ thống E-Voting")
        self.root.geometry("1000x700")
        self.root.configure(bg="#F0F2F5")

        self.style = ttk.Style()
        if "clam" in self.style.theme_names():
            self.style.theme_use("clam")
        
        self.style.configure("TFrame", background="#F0F2F5")
        self.style.configure("TNotebook", background="#F0F2F5", borderwidth=0)
        self.style.configure("TNotebook.Tab", font=("Segoe UI", 10, "bold"), padding=[15, 8], background="#E4E6EB", foreground="#333333")
        self.style.map("TNotebook.Tab", background=[("selected", "#1976D2")], foreground=[("selected", "white")])
        self.style.configure("Treeview", font=("Segoe UI", 10), rowheight=30, borderwidth=0, background="#FFFFFF", fieldbackground="#FFFFFF")
        self.style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"), background="#E4E6EB", foreground="#333333", padding=5)
        self.style.map("Treeview", background=[("selected", "#E3F2FD")], foreground=[("selected", "#000000")])
        self.style.configure("TLabelframe", background="#FFFFFF", borderwidth=1, bordercolor="#D1D5DB")
        self.style.configure("TLabelframe.Label", background="#FFFFFF", font=("Segoe UI", 11, "bold"), foreground="#1976D2")

        self.container = ttk.Frame(root)
        self.container.pack(fill="both", expand=True)
        
        self.container.grid_rowconfigure(0, weight=1)
        self.container.grid_columnconfigure(0, weight=1)
        
        self.frames = {}
        
        for F in (LoginFrame, MainAppFrame, AdminAppFrame):
            page_name = F.__name__
            frame = F(parent=self.container, controller=self)
            self.frames[page_name] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame("LoginFrame")

    def show_frame(self, page_name):
        frame = self.frames[page_name]
        frame.tkraise()
        if (page_name == "MainAppFrame" or page_name == "AdminAppFrame") and CURRENT_USER:
            frame.on_show()

    def on_closing(self):
        if CURRENT_USER:
            db.logout_user(CURRENT_USER['id'])
        self.root.destroy()


class LoginFrame(ttk.Frame):
    def __init__(self, parent, controller):
        ttk.Frame.__init__(self, parent)
        self.controller = controller
        
        box = tk.Frame(self, bg="#FFFFFF", padx=50, pady=50, relief=tk.FLAT, bd=0)
        box.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        box_border = tk.Frame(self, bg="#D1D5DB", padx=1, pady=1)
        box_border.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        box.lift()
        
        tk.Label(box, text="HỆ THỐNG E-VOTING", font=("Segoe UI", 22, "bold"), fg="#1976D2", bg="#FFFFFF").pack(pady=(0, 5))
        tk.Label(box, text="Bảo mật bởi Hệ mật mã Rabin", font=("Segoe UI", 11, "italic"), fg="#65676B", bg="#FFFFFF").pack(pady=(0, 30))
        
        tk.Label(box, text="Tên đăng nhập:", font=("Segoe UI", 10, "bold"), bg="#FFFFFF", fg="#333333").pack(anchor="w")
        self.user_entry = tk.Entry(box, font=("Segoe UI", 12), width=30, relief=tk.SOLID, bd=1)
        self.user_entry.pack(pady=(5, 15), ipady=5)
        
        tk.Label(box, text="Mật khẩu:", font=("Segoe UI", 10, "bold"), bg="#FFFFFF", fg="#333333").pack(anchor="w")
        self.pass_entry = tk.Entry(box, show="•", font=("Segoe UI", 12), width=30, relief=tk.SOLID, bd=1)
        self.pass_entry.pack(pady=(5, 25), ipady=5)
        
        btn_frame = tk.Frame(box, bg="#FFFFFF")
        btn_frame.pack(fill="x")
        
        self.btn_login = tk.Button(btn_frame, text="ĐĂNG NHẬP", bg="#1976D2", fg="white", font=("Segoe UI", 10, "bold"), 
                  relief=tk.FLAT, cursor="hand2", command=self.do_login)
        self.btn_login.pack(side=tk.LEFT, fill="x", expand=True, padx=(0, 5), ipady=8)
        
        self.btn_register = tk.Button(btn_frame, text="ĐĂNG KÝ", bg="#FF9800", fg="white", font=("Segoe UI", 10, "bold"), 
                  relief=tk.FLAT, cursor="hand2", command=self.do_register)
        self.btn_register.pack(side=tk.RIGHT, fill="x", expand=True, padx=(5, 0), ipady=8)

    def do_login(self):
        u = self.user_entry.get().strip()
        p = self.pass_entry.get().strip()
        self.btn_login.config(state=tk.DISABLED, text="ĐANG XỬ LÝ...")
        threading.Thread(target=self._thread_login, args=(u, p), daemon=True).start()

    def _thread_login(self, u, p):
        user = db.login_user(u, p)
        self.after(0, lambda: self._on_login_done(user))

    def _on_login_done(self, user):
        self.btn_login.config(state=tk.NORMAL, text="ĐĂNG NHẬP")
        if user:
            global CURRENT_USER
            CURRENT_USER = user
            if CURRENT_USER['role'].upper() == 'ADMIN':
                self.controller.show_frame("AdminAppFrame")
            else:
                self.controller.show_frame("MainAppFrame")
        else:
            messagebox.showerror("Lỗi", "Sai thông tin đăng nhập!")

    def do_register(self):
        u = self.user_entry.get().strip()
        p = self.pass_entry.get().strip()
        if not u or not p:
            messagebox.showwarning("Cảnh báo", "Vui lòng nhập đủ thông tin!")
            return
        self.btn_register.config(state=tk.DISABLED, text="ĐANG XỬ LÝ...")
        threading.Thread(target=self._thread_register, args=(u, p), daemon=True).start()

    def _thread_register(self, u, p):
        success = db.register_user(u, p, u)
        self.after(0, lambda: self._on_register_done(success))

    def _on_register_done(self, success):
        self.btn_register.config(state=tk.NORMAL, text="ĐĂNG KÝ")
        if success:
            messagebox.showinfo("Thành công", "Đăng ký thành công! Hãy đăng nhập.")
        else:
            messagebox.showerror("Lỗi", "Tài khoản đã tồn tại.")


class MainAppFrame(ttk.Frame):
    def __init__(self, parent, controller):
        ttk.Frame.__init__(self, parent)
        self.controller = controller
        
        header_frame = tk.Frame(self, bg="#1976D2", padx=20, pady=15)
        header_frame.pack(fill="x")

        self.lbl_header = tk.Label(header_frame, text="Xin chào!", font=("Segoe UI", 12, "bold"), fg="white", bg="#1976D2")
        self.lbl_header.pack(side=tk.LEFT)

        tk.Button(header_frame, text="🚪 Đăng xuất", bg="#D32F2F", fg="white", font=("Segoe UI", 9, "bold"), 
                  relief=tk.FLAT, cursor="hand2", padx=10, pady=5, command=self.do_logout).pack(side=tk.RIGHT)

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=20, pady=15)

        self.tab_vote = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_vote, text=" 🗳️ Tham gia Bỏ phiếu ")
        self.setup_vote_tab()

        self.tab_manage = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_manage, text=" 👑 Quản lý Phòng của tôi ")
        self.setup_manage_tab()

    def on_show(self):
        self.lbl_header.config(text=f"👤 {CURRENT_USER['full_name']}   |   Vai trò: {CURRENT_USER['role']}")
        self.load_public_elections()
        self.load_my_elections()

    def do_logout(self):
        global CURRENT_USER
        if CURRENT_USER:
            db.logout_user(CURRENT_USER['id'])
            CURRENT_USER = None
            
        for item in self.tree_elections.get_children(): self.tree_elections.delete(item)
        for item in self.tree_my_rooms.get_children(): self.tree_my_rooms.delete(item)
            
        self.log_text.delete(1.0, tk.END)
        if hasattr(self, 'current_report_data'): self.current_report_data = [] 
            
        self.btn_export_excel.config(state=tk.DISABLED)
        self.btn_open_excel.config(state=tk.DISABLED)
        
        self.new_room_entry.delete(0, tk.END)
        self.room_options_entry.delete(0, tk.END)
        self.room_pass_entry.delete(0, tk.END)
        self.vote_type_var.set("free")
        self.toggle_options()
            
        self.controller.show_frame("LoginFrame")

    # ================= TAB 1: ĐI VOTE =================
    def setup_vote_tab(self):
        top_frame = ttk.Frame(self.tab_vote)
        top_frame.pack(fill="x", pady=10, padx=10)
        
        tk.Button(top_frame, text="🔄 Làm mới danh sách", bg="#65676B", fg="white", font=("Segoe UI", 9, "bold"),
                  relief=tk.FLAT, cursor="hand2", padx=10, pady=5, command=self.load_public_elections).pack(side=tk.LEFT)

        columns = ("id", "name", "creator")
        self.tree_elections = ttk.Treeview(self.tab_vote, columns=columns, show="headings", height=12)
        self.tree_elections.heading("id", text="ID Phòng")
        self.tree_elections.heading("name", text="Tên Cuộc Bầu Cử")
        self.tree_elections.heading("creator", text="Người Tổ Chức")
        self.tree_elections.column("id", width=80, anchor="center")
        self.tree_elections.pack(fill="both", expand=True, padx=10, pady=5)

        btn_frame = ttk.Frame(self.tab_vote)
        btn_frame.pack(fill="x", pady=15)
        tk.Button(btn_frame, text="🚪 VÀO PHÒNG BỎ PHIẾU", bg="#4CAF50", fg="white", font=("Segoe UI", 12, "bold"), 
                  relief=tk.FLAT, cursor="hand2", padx=20, pady=8, command=self.open_room_popup).pack()
        self.tree_elections.bind("<Double-1>", lambda event: self.open_room_popup())

    def load_public_elections(self):
        threading.Thread(target=self._thread_load_public, daemon=True).start()

    def _thread_load_public(self):
        elections = db.get_all_active_elections()
        self.after(0, lambda: self._on_load_public_done(elections))

    def _on_load_public_done(self, elections):
        for item in self.tree_elections.get_children():
            self.tree_elections.delete(item)
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
            messagebox.showerror("Từ chối", "Bạn đã bỏ phiếu trong phòng này rồi. Mỗi người chỉ được 1 phiếu!")
            return

        election = db.get_election_by_id(election_id)
        # 1. Chặn nếu phòng bị khóa thủ công
        if not election.get('is_active'):
            messagebox.showerror("Từ chối", "Phòng bỏ phiếu này đã bị Chủ phòng đóng cửa!")
            return
            
        # 2. Chặn nếu quá thời gian hẹn giờ
        end_time_str = election.get('end_time')
        if end_time_str:
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M")
            if current_time > end_time_str:
                messagebox.showerror("Hết hạn", f"Cuộc bầu cử này đã kết thúc vào lúc {end_time_str}!\nBạn không thể bỏ phiếu nữa.")
                # Tự động update trạng thái khóa luôn cho tiện
                db.toggle_election_status(election_id, False)
                self.load_public_elections()
                return
        real_password = election.get('room_password')
        if real_password:
            entered_pass = simpledialog.askstring("Xác thực", f"Phòng '{election_name}' yêu cầu mật khẩu:\n", parent=self, show='•')
            if entered_pass is None: return
            if entered_pass != real_password:
                messagebox.showerror("Từ chối", "Sai mật khẩu phòng!")
                return
        
        popup = tk.Toplevel(self)
        popup.title("Bỏ phiếu ẩn danh")
        popup.geometry("550x500") # Mở rộng không gian hiển thị ban đầu
        popup.minsize(500, 400)   # Đặt giới hạn không cho phép thu nhỏ quá mức
        popup.configure(bg="#FFFFFF")
        popup.grab_set() 
        
        tk.Label(popup, text=f"🗳️ {election_name}", font=("Segoe UI", 16, "bold"), fg="#1976D2", bg="#FFFFFF").pack(pady=(20,5))
        tk.Label(popup, text=f"Chủ phòng: {host_name}", font=("Segoe UI", 10, "italic"), fg="#65676B", bg="#FFFFFF").pack()
        
        # --- NEO NÚT BẤM XUỐNG DƯỚI CÙNG (Để nó không bao giờ bị đè) ---
        btn_submit_vote = tk.Button(popup, text="🚀 CHỐT PHIẾU (MÃ HÓA)", bg="#D32F2F", fg="white", font=("Segoe UI", 12, "bold"), 
                  relief=tk.FLAT, cursor="hand2", padx=20, pady=8)
        btn_submit_vote.pack(side=tk.BOTTOM, pady=(10, 20))

        # --- TẠO KHUNG CÓ THANH CUỘN DÀNH CHO CÁC LỰA CHỌN ---
        container = tk.Frame(popup, bg="#FFFFFF")
        container.pack(fill="both", expand=True, padx=30, pady=10) # expand=True giúp khu vực này tự chiếm hết khoảng trống ở giữa
        
        canvas = tk.Canvas(container, bg="#FFFFFF", highlightthickness=0)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        frame_input = tk.Frame(canvas, bg="#FFFFFF")
        
        # Lệnh ma thuật giúp Canvas tự co giãn theo chiều cao của tất cả lựa chọn
        frame_input.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=frame_input, anchor="nw", width=460)
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # --- LOGIC XỬ LÝ LỰA CHỌN ---
        popup.choice_var = tk.StringVar(popup)
        
        if election.get('vote_type') == 'fixed':
            popup.choice_var.set("___UNSELECTED___")
            tk.Label(frame_input, text="Lựa chọn của bạn:", font=("Segoe UI", 11, "bold"), bg="#FFFFFF").pack(anchor="w", pady=(0, 10))
            
            options_str = election.get('options', '')
            if options_str:
                options_list = [opt.strip() for opt in options_str.split(',')]
                for opt in options_list:
                    # Wraplength=420 giúp câu chữ dài tự động xuống dòng không bị cắt chữ
                    tk.Radiobutton(frame_input, text=opt, variable=popup.choice_var, value=opt, 
                                   font=("Segoe UI", 11), bg="#FFFFFF", activebackground="#FFFFFF", 
                                   cursor="hand2", wraplength=420, justify="left").pack(anchor="w", pady=5)
        else:
            popup.choice_var.set("")
            tk.Label(frame_input, text="Nhập ý kiến bỏ phiếu:", font=("Segoe UI", 11, "bold"), bg="#FFFFFF").pack(anchor="w", pady=(0, 10))
            entry = tk.Entry(frame_input, textvariable=popup.choice_var, font=("Segoe UI", 12), relief=tk.SOLID, bd=1)
            entry.pack(fill="x", pady=5, ipady=6, padx=(0, 20))
            
        def submit_popup_vote():
            choice = popup.choice_var.get().strip()
            if not choice or choice == "___UNSELECTED___":
                messagebox.showwarning("Cảnh báo", "Vui lòng đưa ra quyết định trước khi chốt phiếu!", parent=popup)
                return
            
            btn_submit_vote.config(state=tk.DISABLED, text="ĐANG MÃ HÓA...")
            threading.Thread(target=_thread_submit_vote, args=(choice,), daemon=True).start()

        def _thread_submit_vote(choice):
            try:
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

                success = db.submit_vote(CURRENT_USER['id'], election_id, cipher_ballot, voter_key['n'], voter_sig)
                self.after(0, lambda: _on_submit_done(success))
            except Exception as e:
                self.after(0, lambda: _on_submit_done(False, str(e)))

        def _on_submit_done(success, error_msg=""):
            if success:
                messagebox.showinfo("Thành công", "Bỏ phiếu thành công!\nDữ liệu đã được mã hóa an toàn.", parent=popup)
                popup.destroy() 
                self.load_public_elections() 
            else:
                btn_submit_vote.config(state=tk.NORMAL, text="🚀 CHỐT PHIẾU (MÃ HÓA)")
                messagebox.showerror("Lỗi", f"Có lỗi xảy ra: {error_msg}", parent=popup)

        # Gán lệnh thực thi vào nút bấm
        btn_submit_vote.config(command=submit_popup_vote)

    # ================= TAB 2: QUẢN LÝ PHÒNG =================
    def setup_manage_tab(self):
        create_frame = ttk.LabelFrame(self.tab_manage, text=" ✚ Tạo phòng bầu cử mới ", padding=15)
        create_frame.pack(fill="x", padx=10, pady=10)
        
        tk.Label(create_frame, text="Tên phòng:", font=("Segoe UI", 10), bg="#FFFFFF").grid(row=0, column=0, sticky="w", pady=5)
        self.new_room_entry = tk.Entry(create_frame, font=("Segoe UI", 11), width=35, relief=tk.SOLID, bd=1)
        self.new_room_entry.grid(row=0, column=1, sticky="w", pady=5, ipady=3)

        self.vote_type_var = tk.StringVar(value="free")
        radio_frame = tk.Frame(create_frame, bg="#FFFFFF")
        radio_frame.grid(row=1, column=0, columnspan=2, sticky="w", pady=5)
        tk.Radiobutton(radio_frame, text="Bỏ phiếu Tự do", variable=self.vote_type_var, value="free", bg="#FFFFFF", activebackground="#FFFFFF", cursor="hand2", command=self.toggle_options).pack(side=tk.LEFT, padx=(0, 20))
        tk.Radiobutton(radio_frame, text="Lựa chọn Có sẵn", variable=self.vote_type_var, value="fixed", bg="#FFFFFF", activebackground="#FFFFFF", cursor="hand2", command=self.toggle_options).pack(side=tk.LEFT)

        tk.Label(create_frame, text="Các lựa chọn (phân cách dấu phẩy):", font=("Segoe UI", 10), bg="#FFFFFF").grid(row=2, column=0, sticky="w", pady=5, padx=(0,10))
        self.room_options_entry = tk.Entry(create_frame, font=("Segoe UI", 11), width=35, relief=tk.SOLID, bd=1, state="disabled")
        self.room_options_entry.grid(row=2, column=1, sticky="w", pady=5, ipady=3)

        tk.Label(create_frame, text="Mật khẩu phòng (Tùy chọn):", font=("Segoe UI", 10), bg="#FFFFFF").grid(row=3, column=0, sticky="w", pady=5)
        self.room_pass_entry = tk.Entry(create_frame, font=("Segoe UI", 11), width=35, relief=tk.SOLID, bd=1)
        self.room_pass_entry.grid(row=3, column=1, sticky="w", pady=5, ipady=3)

        # THÊM Ô NHẬP HẸN GIỜ ĐÓNG CỬA
        tk.Label(create_frame, text="Hạn chót (YYYY-MM-DD HH:MM):", font=("Segoe UI", 10), bg="#FFFFFF").grid(row=4, column=0, sticky="w", pady=5)
        self.room_deadline_entry = tk.Entry(create_frame, font=("Segoe UI", 11), width=35, relief=tk.SOLID, bd=1)
        self.room_deadline_entry.grid(row=4, column=1, sticky="w", pady=5, ipady=3)

        self.btn_create_room = tk.Button(create_frame, text="TẠO PHÒNG", bg="#1976D2", fg="white", font=("Segoe UI", 11, "bold"), 
                  relief=tk.FLAT, cursor="hand2", command=self.create_room)
        self.btn_create_room.grid(row=0, column=2, rowspan=5, padx=30, ipadx=10, ipady=15)

        list_frame = ttk.LabelFrame(self.tab_manage, text=" 📊 Quản lý và Kiểm phiếu ", padding=15)
        list_frame.pack(fill="both", expand=True, padx=10, pady=5)

        cols = ("id", "name", "status")
        self.tree_my_rooms = ttk.Treeview(list_frame, columns=cols, show="headings", height=4)
        self.tree_my_rooms.heading("id", text="ID")
        self.tree_my_rooms.heading("name", text="Tên Phòng")
        self.tree_my_rooms.heading("status", text="Trạng thái")
        self.tree_my_rooms.column("id", width=80, anchor="center")
        self.tree_my_rooms.column("status", width=120, anchor="center")
        self.tree_my_rooms.pack(fill="x", pady=(0, 10))
        
        self.tree_my_rooms.bind("<<TreeviewSelect>>", self.on_room_select)
        
        btn_action_frame = tk.Frame(list_frame, bg="#FFFFFF")
        btn_action_frame.pack(fill="x", pady=5)
        
        self.btn_check_votes = tk.Button(btn_action_frame, text="📥 KIỂM PHIẾU (GIẢI MÃ)", bg="#388E3C", fg="white", font=("Segoe UI", 10, "bold"), relief=tk.FLAT, cursor="hand2", padx=10, pady=5, command=self.process_my_room)
        self.btn_check_votes.pack(side=tk.LEFT, padx=(0, 10))

        # 2 NÚT MỚI: KHÓA VÀ XÓA PHÒNG
        self.btn_toggle_room = tk.Button(btn_action_frame, text="🔒 KHÓA/MỞ PHÒNG", bg="#757575", fg="white", font=("Segoe UI", 10, "bold"), relief=tk.FLAT, cursor="hand2", padx=10, pady=5, command=self.toggle_room, state=tk.DISABLED)
        self.btn_toggle_room.pack(side=tk.LEFT, padx=10)
        
        self.btn_delete_room = tk.Button(btn_action_frame, text="🗑️ XÓA PHÒNG", bg="#D32F2F", fg="white", font=("Segoe UI", 10, "bold"), relief=tk.FLAT, cursor="hand2", padx=10, pady=5, command=self.delete_room, state=tk.DISABLED)
        self.btn_delete_room.pack(side=tk.LEFT, padx=10)
        
        self.btn_export_excel = tk.Button(btn_action_frame, text="📊 XUẤT BÁO CÁO", bg="#FF9800", fg="white", font=("Segoe UI", 10, "bold"), relief=tk.FLAT, cursor="hand2", padx=10, pady=5, command=self.export_to_excel, state=tk.DISABLED)
        self.btn_export_excel.pack(side=tk.RIGHT, padx=(10, 0))
        
        self.btn_open_excel = tk.Button(btn_action_frame, text="📂 MỞ FILE", bg="#1976D2", fg="white", font=("Segoe UI", 10, "bold"), relief=tk.FLAT, cursor="hand2", padx=10, pady=5, command=self.open_excel_file, state=tk.DISABLED)
        self.btn_open_excel.pack(side=tk.RIGHT, padx=10)
        
        self.log_text = scrolledtext.ScrolledText(list_frame, height=6, font=("Consolas", 10), bg="#F8F9FA", relief=tk.SOLID, bd=1)
        self.log_text.pack(fill="both", expand=True, pady=(15, 0))

    def toggle_options(self):
        if self.vote_type_var.get() == "fixed":
            self.room_options_entry.config(state="normal", bg="#FFFFFF")
        else:
            self.room_options_entry.delete(0, tk.END)
            self.room_options_entry.config(state="disabled", bg="#F0F2F5")

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
        if not room_password: room_password = None

        # Bắt lỗi thời gian nhập vào
        end_time = self.room_deadline_entry.get().strip()
        if end_time:
            try:
                datetime.strptime(end_time, "%Y-%m-%d %H:%M")
            except ValueError:
                messagebox.showerror("Lỗi", "Định dạng thời gian không đúng!\nVui lòng nhập chuẩn: YYYY-MM-DD HH:MM\nVí dụ: 2026-12-31 23:59")
                return
        else:
            end_time = None

        if vote_type == 'fixed' and not options:
            messagebox.showwarning("Lỗi", "Vui lòng nhập các lựa chọn cho phòng!")
            return
        
        self.btn_create_room.config(state=tk.DISABLED, text="ĐANG TẠO...")
        self.log_text.insert(tk.END, f"[*] Đang sinh Master Key (Rabin) cho phòng '{name}' ở luồng nền...\n")
        self.log_text.see(tk.END)
        
        # TRUYỀN THÊM end_time VÀO THREAD
        threading.Thread(target=self._thread_create_room, args=(name, vote_type, options, room_password, end_time), daemon=True).start()

    def _thread_create_room(self, name, vote_type, options, room_password, end_time):
        try:
            key = rabin.rabin_keygen(bits=2048)
            election_id = db.create_election(name, key['n'], CURRENT_USER['id'], vote_type, options, key, room_password, end_time)
            self.after(0, lambda: self._on_create_room_done(True, election_id, room_password, end_time))
        except Exception as e:
            self.after(0, lambda: self._on_create_room_done(False, str(e), None, None))

    def _on_create_room_done(self, success, result, room_password, end_time):
        self.btn_create_room.config(state=tk.NORMAL, text="TẠO PHÒNG")
        if success:
            election_id = result
            self.log_text.insert(tk.END, f"[OK] Tạo phòng thành công! ID = {election_id}\n")
            if room_password: self.log_text.insert(tk.END, f"[🔒] Phòng được bảo mật bằng mật khẩu.\n")
            if end_time: self.log_text.insert(tk.END, f"[⏰] Tự động đóng cửa bỏ phiếu sau: {end_time}.\n")
            self.log_text.see(tk.END)
            
            self.new_room_entry.delete(0, tk.END)
            self.room_options_entry.delete(0, tk.END)
            self.room_pass_entry.delete(0, tk.END)
            self.room_deadline_entry.delete(0, tk.END)
            self.load_my_elections()
            self.load_public_elections()
        else:
            messagebox.showerror("Lỗi", f"Không thể tạo phòng: {result}")

    # HÀM XỬ LÝ KHÓA VÀ XÓA
    def toggle_room(self):
        selected = self.tree_my_rooms.selection()
        if not selected: return
        election_id = self.tree_my_rooms.item(selected[0])['values'][0]
        status_text = self.tree_my_rooms.item(selected[0])['values'][2]
        
        new_status = False if status_text == "Đang mở" else True
        if db.toggle_election_status(election_id, new_status):
            msg = "Khóa phòng" if not new_status else "Mở lại phòng"
            self.log_text.insert(tk.END, f"[*] Đã {msg} thành công cho ID: {election_id}\n")
            self.load_my_elections()
            self.load_public_elections()

    def delete_room(self):
        selected = self.tree_my_rooms.selection()
        if not selected: return
        election_id = self.tree_my_rooms.item(selected[0])['values'][0]
        election_name = self.tree_my_rooms.item(selected[0])['values'][1]
        
        confirm = messagebox.askyesno("Cảnh báo nguy hiểm", f"Bạn có chắc chắn muốn xóa phòng '{election_name}'?\nToàn bộ phiếu bầu cũng sẽ bị xóa và không thể khôi phục!")
        if confirm:
            if db.delete_election(election_id):
                self.log_text.insert(tk.END, f"[🗑️] Đã xóa phòng '{election_name}' (ID: {election_id})\n")
                self.load_my_elections()
                self.load_public_elections()

    def on_room_select(self, event):
        selected = self.tree_my_rooms.selection()
        if not selected: return
        election_id = self.tree_my_rooms.item(selected[0])['values'][0]
        
        # Mở khóa 2 nút thao tác
        self.btn_toggle_room.config(state=tk.NORMAL)
        self.btn_delete_room.config(state=tk.NORMAL)
        
        self.btn_export_excel.config(state=tk.DISABLED)
        report_dir = config.PROJECT_ROOT / "reports"
        file_path = report_dir / f"BaoCao_Phong_{election_id}.csv"
        if file_path.exists():
            self.btn_open_excel.config(state=tk.NORMAL)
        else:
            self.btn_open_excel.config(state=tk.DISABLED)

    def process_my_room(self):
        selected = self.tree_my_rooms.selection()
        if not selected:
            messagebox.showwarning("Nhắc nhở", "Vui lòng chọn 1 phòng trong bảng để kiểm phiếu!")
            return
            
        election_id = self.tree_my_rooms.item(selected[0])['values'][0]
        election_name = self.tree_my_rooms.item(selected[0])['values'][1]
        
        election = db.get_election_by_id(election_id)
        if not election or not election.get('authority_priv'):
            messagebox.showerror("Lỗi", "Không tìm thấy Khóa Bí Mật của phòng này trên Cloud!")
            return
            
        auth_priv = json.loads(election['authority_priv'])
        all_votes = db.get_all_votes_by_election(election_id)
        
        self.btn_check_votes.config(state=tk.DISABLED, text="ĐANG GIẢI MÃ...")
        self.log_text.insert(tk.END, f"\n========== KẾT QUẢ KIỂM PHIẾU: {election_name} ==========\n")
        self.log_text.insert(tk.END, f"[*] Đang chạy thuật toán giải mã ở luồng nền...\n")
        self.log_text.see(tk.END)
        
        threading.Thread(target=self._thread_process_room, args=(election_id, election_name, auth_priv, all_votes), daemon=True).start()

    def _thread_process_room(self, election_id, election_name, auth_priv, all_votes):
        valid_count = invalid_count = 0
        tally_results = {}
        report_data = []
        
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
                    tally_results[choice] = tally_results.get(choice, 0) + 1
                    report_data.append([election_id, election_name, vote['id'], "HỢP LỆ", choice, ""])
                        
                elif vote['status'] == 'INVALID':
                    invalid_count += 1
                    report_data.append([election_id, election_name, vote['id'], "KHÔNG HỢP LỆ", "N/A", "Sai chữ ký số"])
                    
            except Exception as e:
                if vote['status'] == 'PENDING': db.update_vote_status(vote['id'], 'INVALID')
                invalid_count += 1
                report_data.append([election_id, election_name, vote['id'], "LỖI KỸ THUẬT", "N/A", str(e)])
                
        self.after(0, lambda: self._on_process_room_done(election_id, valid_count, invalid_count, tally_results, report_data))

    def _on_process_room_done(self, election_id, valid_count, invalid_count, tally_results, report_data):
        self.btn_check_votes.config(state=tk.NORMAL, text="📥 KIỂM PHIẾU (GIẢI MÃ)")
        self.current_report_data = report_data
        self.current_election_id = election_id
        
        self.log_text.insert(tk.END, f"✔️ Số phiếu HỢP LỆ: {valid_count}\n")
        self.log_text.insert(tk.END, f"❌ Số phiếu KHÔNG HỢP LỆ: {invalid_count}\n\n")
        self.log_text.insert(tk.END, f"🏆 TỔNG KẾT BẦU CỬ:\n")
        if not tally_results:
            self.log_text.insert(tk.END, f"  Chưa có phiếu hợp lệ nào.\n")
        else:
            for choice, count in tally_results.items():
                self.log_text.insert(tk.END, f"   ➤ {choice}: {count} phiếu\n")
        self.log_text.insert(tk.END, f"--------------------------------------------------\n")
        self.log_text.insert(tk.END, f"Gợi ý: Bấm 'XUẤT BÁO CÁO' để ghi Log Kiểm toán.\n")
        self.log_text.see(tk.END)
        self.btn_export_excel.config(state=tk.NORMAL)

    def export_to_excel(self):
        if not hasattr(self, 'current_report_data') or not self.current_report_data: return
        report_dir = config.PROJECT_ROOT / "reports"
        report_dir.mkdir(exist_ok=True)
        file_path = report_dir / f"BaoCao_Phong_{self.current_election_id}.csv"
        try:
            with open(file_path, 'w', newline='', encoding='utf-8-sig') as f:
                writer = csv.writer(f)
                writer.writerow(["Mã Phòng", "Tên Phòng", "Mã Lá Phiếu (Vote ID)", "Trạng Thái", "Lựa Chọn", "Ghi Chú"])
                for row in self.current_report_data: writer.writerow(row)
            self.log_text.insert(tk.END, f"[*] Đã xuất Audit Log tại: {file_path.name}\n\n")
            self.log_text.see(tk.END)
            self.btn_open_excel.config(state=tk.NORMAL)
            messagebox.showinfo("Hoàn tất", f"Xuất báo cáo thành công!")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể lưu file: {e}")

    def open_excel_file(self):
        selected = self.tree_my_rooms.selection()
        if not selected: return
        election_id = self.tree_my_rooms.item(selected[0])['values'][0]
        file_path = config.PROJECT_ROOT / "reports" / f"BaoCao_Phong_{election_id}.csv"
        if file_path.exists():
            try: os.startfile(file_path)
            except AttributeError:
                import subprocess; subprocess.call(('open', file_path))
        else: messagebox.showerror("Lỗi", "Không tìm thấy file!")

class AdminAppFrame(ttk.Frame):
    def __init__(self, parent, controller):
        ttk.Frame.__init__(self, parent)
        self.controller = controller
        self.auto_refresh_id = None
        
        # Header Admin
        header_frame = tk.Frame(self, bg="#D32F2F", padx=20, pady=15)
        header_frame.pack(fill="x")

        self.lbl_header = tk.Label(header_frame, text="⚙️ ADMIN DASHBOARD", font=("Segoe UI", 12, "bold"), fg="white", bg="#D32F2F")
        self.lbl_header.pack(side=tk.LEFT)

        tk.Button(header_frame, text="🚪 Đăng xuất", bg="#B71C1C", fg="white", font=("Segoe UI", 9, "bold"), 
                  relief=tk.FLAT, cursor="hand2", padx=10, pady=5, command=self.do_logout).pack(side=tk.RIGHT)
        tk.Button(header_frame, text="🔄 Làm mới Data", bg="#1976D2", fg="white", font=("Segoe UI", 9, "bold"), 
                  relief=tk.FLAT, cursor="hand2", padx=10, pady=5, command=self.load_all_data).pack(side=tk.RIGHT, padx=15)

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=20, pady=15)

        # TAB 1: USERS
        self.tab_users = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_users, text=" 👥 Hệ thống Users ")
        self.tree_users = ttk.Treeview(self.tab_users, columns=("id", "username", "name", "role", "online"), show="headings")
        self.tree_users.heading("id", text="ID"); self.tree_users.column("id", width=50, anchor="center")
        self.tree_users.heading("username", text="Tên đăng nhập")
        self.tree_users.heading("name", text="Họ Tên")
        self.tree_users.heading("role", text="Quyền"); self.tree_users.column("role", width=100, anchor="center")
        self.tree_users.heading("online", text="Trạng thái"); self.tree_users.column("online", width=100, anchor="center")
        self.tree_users.pack(fill="both", expand=True, padx=10, pady=10)

        # TAB 2: ELECTIONS
        self.tab_elections = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_elections, text=" 🗳️ Quản trị Phòng Bầu Cử ")
        self.tree_elections = ttk.Treeview(self.tab_elections, columns=("id", "name", "creator", "type", "active", "pass"), show="headings")
        self.tree_elections.heading("id", text="ID"); self.tree_elections.column("id", width=50, anchor="center")
        self.tree_elections.heading("name", text="Tên Phòng")
        self.tree_elections.heading("creator", text="ID Chủ phòng"); self.tree_elections.column("creator", width=100, anchor="center")
        self.tree_elections.heading("type", text="Luật chơi"); self.tree_elections.column("type", width=80, anchor="center")
        self.tree_elections.heading("active", text="Status"); self.tree_elections.column("active", width=80, anchor="center")
        self.tree_elections.heading("pass", text="Mật khẩu"); self.tree_elections.column("pass", width=100, anchor="center")
        self.tree_elections.pack(fill="both", expand=True, padx=10, pady=10)

        # TAB 3: VOTES
        self.tab_votes = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_votes, text=" 📨 Audit Log (Phiếu Bầu) ")
        self.tree_votes = ttk.Treeview(self.tab_votes, columns=("id", "user_id", "election_id", "status"), show="headings")
        self.tree_votes.heading("id", text="ID Phiếu"); self.tree_votes.column("id", width=80, anchor="center")
        self.tree_votes.heading("user_id", text="ID Cử tri"); self.tree_votes.column("user_id", width=100, anchor="center")
        self.tree_votes.heading("election_id", text="ID Phòng"); self.tree_votes.column("election_id", width=100, anchor="center")
        self.tree_votes.heading("status", text="Trạng thái phân tích"); self.tree_votes.column("status", width=200, anchor="center")
        self.tree_votes.pack(fill="both", expand=True, padx=10, pady=10)

    def on_show(self):
        self.lbl_header.config(text=f"⚙️ TỔNG TRẠM QUẢN TRỊ  |  Admin: {CURRENT_USER['username']}")
        self.load_all_data()
        self.auto_refresh()

    def load_all_data(self):
        # Cho Admin thì load nhanh luôn vì không làm ảnh hưởng tác vụ User
        for tree in [self.tree_users, self.tree_elections, self.tree_votes]:
            for item in tree.get_children(): tree.delete(item)
        for u in db.get_all_users_admin():
            self.tree_users.insert("", "end", values=(u['id'], u['username'], u['full_name'], u['role'], "🟢 Online" if u['is_online'] else "🔴 Offline"))
        for e in db.get_all_elections_admin():
            has_pass = "Có" if e['room_password'] else "Không"
            self.tree_elections.insert("", "end", values=(e['id'], e['name'], e['creator_id'], e['vote_type'], "Mở" if e['is_active'] else "Đóng", has_pass))
        for v in db.get_all_votes_admin():
            self.tree_votes.insert("", "end", values=(v['id'], v['user_id'], v['election_id'], v['status']))

    def auto_refresh(self):
        if CURRENT_USER and CURRENT_USER['role'].upper() == 'ADMIN':
            self.load_all_data()
            self.auto_refresh_id = self.after(5000, self.auto_refresh)

    def do_logout(self):
        global CURRENT_USER
        if self.auto_refresh_id: self.after_cancel(self.auto_refresh_id)
        if CURRENT_USER:
            db.logout_user(CURRENT_USER['id'])
            CURRENT_USER = None
        for tree in [self.tree_users, self.tree_elections, self.tree_votes]:
            for item in tree.get_children(): tree.delete(item)
        self.controller.show_frame("LoginFrame")

if __name__ == "__main__":
    root = tk.Tk()
    app = UserApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()