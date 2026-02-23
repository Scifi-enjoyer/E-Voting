"""
gui_authority.py
Giao diện (TKinter) cho Authority (Bên kiểm phiếu).
Cho phép quản lý NHIỀU cấu hình bầu cử.
Cho phép XEM KẾT QUẢ theo từng cuộc bầu cử.
"""

import tkinter as tk
from tkinter import scrolledtext, messagebox
from pathlib import Path
import sys, os, io, json

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(project_root)

try:
    import config
    import src.authority as authority
    import src.utils_rabin as rabin 
except ImportError as e:
    messagebox.showerror("Lỗi Import", f"Không thể import module cần thiết: {e}\n"
                         "Hãy đảm bảo file này nằm ở thư mục gốc rabin_voting/.")
    sys.exit(1)


class StdoutRedirector(io.StringIO):
    # ... (Giữ nguyên) ...
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget
        self.text_widget.config(state='disabled')
    def write(self, s):
        self.text_widget.config(state='normal')
        self.text_widget.insert(tk.END, s)
        self.text_widget.see(tk.END)
        self.text_widget.config(state='disabled')
        io.StringIO.write(self, s)
    def flush(self):
        pass


class AuthorityApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Authority GUI (Quản lý Bầu cử)")
        self.root.geometry("600x800") 
        
        self.available_configs = [] # List [filename1, filename2]
        self.selected_config_file = tk.StringVar(root) # Dùng cho Bước B
        
        # --- BIẾN MỚI CHO BƯỚC D ---
        self.selected_results_election = tk.StringVar(root) # Dùng cho Bước D

        main_frame = tk.Frame(root, padx=10, pady=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # ---- Khung điều khiển (Bước A) ----
        setup_frame_A = tk.Frame(main_frame)
        setup_frame_A.pack(fill=tk.X, pady=5)
        self.keygen_button = tk.Button(setup_frame_A, text="Sinh khóa Authority (Chỉ 1 lần)", 
                                       command=self.run_keygen, bg="#E65100", fg="white",
                                       font=('Arial', 10, 'bold'))
        self.keygen_button.pack(fill=tk.X, expand=True, ipady=5)


        # ---- Khung Thiết lập (Bước B) ----
        setup_frame_B = tk.LabelFrame(main_frame, text="Tạo cấu hình Bầu cử", padx=10, pady=10)
        setup_frame_B.pack(fill=tk.X, pady=5)        
        edit_frame = tk.Frame(setup_frame_B)
        edit_frame.pack(fill=tk.X, pady=5)
        edit_frame.columnconfigure(1, weight=1)

        tk.Label(edit_frame, text="Mã Bầu cử:").grid(row=0, column=0, sticky='e', pady=2)
        self.setup_election_id = tk.Entry(edit_frame)
        self.setup_election_id.grid(row=0, column=1, padx=5, pady=2, sticky='ew',columnspan=2)
        tk.Label(edit_frame, text="Các Vị trí:").grid(row=1, column=0, sticky='e', pady=2)
        self.setup_positions = tk.Entry(edit_frame)
        self.setup_positions.grid(row=1, column=1, padx=5, pady=2, sticky='ew', columnspan=2)
        tk.Label(edit_frame, text="Các lựa chọn:").grid(row=2, column=0, sticky='e', pady=2)
        self.setup_choices = tk.Entry(edit_frame)
        self.setup_choices.grid(row=2, column=1, padx=5, pady=2, sticky='ew', columnspan=2)
        self.save_config_button = tk.Button(edit_frame, text="Lưu cấu hình Bầu cử", 
                                            command=self.save_election_config, bg="#00695C", fg="white")
        self.save_config_button.grid(row=3, column=1, pady=10, padx=5, sticky='ew')
        tk.Label(edit_frame, text="Lưu ý: Các vị trí,lựa chọn viết cách nhau bằng dấu phẩy.").grid(row=4, column=1, sticky='ew')
        tk.Label(edit_frame, text="Ví dụ: Vị trí A,Vị trí B,...").grid(row=5, column=1, sticky='ew')
        

        # ---- Khung Hành động (Bước C) ----
        action_frame = tk.LabelFrame(main_frame, text="Xử lý Phiếu", padx=10, pady=10)
        action_frame.pack(fill=tk.X, pady=5)
        
        # --- BƯỚC C (GIỮ NGUYÊN) ---
        self.verify_button = tk.Button(action_frame, text="Kiểm phiếu", 
                                       command=self.run_verify_all, bg="#1E88E5", fg="white",
                                       font=('Arial', 10, 'bold'))
        self.verify_button.pack(fill=tk.X, expand=True, ipady=5, pady=(0, 10))
        
        
        # --- BƯỚC D (NÂNG CẤP) ---
        results_frame = tk.LabelFrame(main_frame, text="Xem Kết Quả", padx=10, pady=10)
        results_frame.pack(fill=tk.X, pady=(10, 0))
        load_frame = tk.Frame(results_frame)
        load_frame.pack(fill=tk.X, pady=5)
        tk.Label(load_frame, text="Tải cấu hình:").pack(side=tk.LEFT, padx=(0, 5))
        self.results_election_menu = tk.OptionMenu(load_frame, self.selected_results_election, "...")
        self.results_election_menu.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        self.results_button = tk.Button(results_frame,text="Xem Kết Quả",
                                        command=self.run_show_results, bg="#43A047", fg="white",
                                        font=('Arial', 10, 'bold'))
        self.results_button.pack(fill=tk.X, expand=True, ipady=5)
        


        # ---- Khung log output ----
        log_frame = tk.LabelFrame(main_frame, text="Log Output", padx=5, pady=5)
        # ... (Giữ nguyên) ...
        log_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=15, bg="#f0f0f0")
        self.log_text.pack(fill=tk.BOTH, expand=True)
        sys.stdout = StdoutRedirector(self.log_text)
        
        self.refresh_config_list() # Tải danh sách config
        
        print("Hướng dẫn sử dụng chương trình:")
        print("Bước 1: Sinh khóa (nếu chưa có).")
        print("Bước 2:Tải/Tạo/Lưu Cấu hình Bầu cử.")
        print("Bước 3:Kiểm phiếu (xử lý các phiếu mới).")
        print("Bước 4:Chọn cuộc bầu cử và Xem Kết Quả.")
        print("-" * 30)

    def clear_log(self):
        self.log_text.config(state='normal')
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state='disabled')

    def run_keygen(self):
        # ... (Giữ nguyên) ...
        self.clear_log()
        print("--- [AUTH] Bắt đầu sinh khóa (2048 bit)... ---\n")
        try:
            authority.authority_keygen(bits=2048)
            print("\n--- [AUTH] Sinh khóa thành công! ---")
            messagebox.showinfo("Thành công", "Đã sinh khóa Authority thành công!")
        except Exception as e:
            print(f"\n[ERROR] Lỗi khi sinh khóa: {e}")
            messagebox.showerror("Lỗi", f"Có lỗi xảy ra: {e}")

    # --- HÀM CẬP NHẬT ---
    def refresh_config_list(self):
        """Quét thư mục 'elections' và chỉ cập nhật menu KẾT QUẢ."""
        print("[INFO] Đang làm mới danh sách cấu hình bầu cử...")
        config.ELECTIONS_DIR.mkdir(exist_ok=True) 
        
        try:
            self.available_configs = sorted([f.name for f in config.ELECTIONS_DIR.glob("*.json")])
            
            
            # 2. Cập nhật menu "Xem Kết Quả" (Bước D)
            menu_results = self.results_election_menu["menu"]
            menu_results.delete(0, "end")
            
            # --- Thêm lựa chọn "TẤT CẢ" cho menu Kết quả ---
            all_str = "--- TẤT CẢ CUỘC BẦU CỬ ---"
            menu_results.add_command(label=all_str, command=tk._setit(self.selected_results_election, all_str))
            
            if not self.available_configs:
                self.selected_results_election.set(all_str) # Mặc định là TẤT CẢ
            else:
                self.selected_results_election.set(all_str) # Mặc định là TẤT CẢ
                
                for f_name in self.available_configs:                    
                    for f_name in self.available_configs:
                    # --- SỬA Ở ĐÂY ---
                    # Lấy tên sạch (ví dụ: "lop-truong")
                        clean_name = f_name.rsplit('.json', 1)[0]
                    
                    # Thêm vào menu "Xem Kết Quả":
                    # Label = tên sạch, Giá trị lưu trữ = cũng là tên sạch
                    menu_results.add_command(label=clean_name, command=tk._setit(self.selected_results_election, clean_name))
                    # --- HẾT SỬA ---
                    
            print(f"[OK] Tìm thấy {len(self.available_configs)} cấu hình.")
        except Exception as e:
            print(f"[ERROR] Không thể tải danh sách cấu hình: {e}")

    # --- (Hàm load_selected_config giữ nguyên) ---
    def load_selected_config(self):
        """Tải config đã chọn từ menu vào các ô entry."""
        self.clear_log()
        filename = self.selected_config_file.get()
        if not filename:
            print("[WARN] Vui lòng chọn một cấu hình để tải.")
            messagebox.showwarning("Chưa chọn", "Chưa có cấu hình nào để tải.")
            return
        print(f"[INFO] Đang tải cấu hình: {filename}...")
        try:
            config_path = config.ELECTIONS_DIR / filename
            with open(config_path, 'r', encoding='utf-8') as f:
                cfg = json.load(f)
            file_id = filename.rsplit('.json', 1)[0]
            self.setup_election_id.delete(0, tk.END)
            self.setup_election_id.insert(0, file_id) 
            self.setup_positions.delete(0, tk.END)
            self.setup_positions.insert(0, ",".join(cfg.get("positions", [])))
            self.setup_choices.delete(0, tk.END)
            self.setup_choices.insert(0, ",".join(cfg.get("choices", [])))
            print("[OK] Tải thành công.")
        except Exception as e:
            print(f"[ERROR] Không thể tải file {filename}: {e}")
            messagebox.showerror("Lỗi Tải file", f"Không thể đọc file {filename}:\n{e}")

    # --- (Hàm save_election_config giữ nguyên) ---
    def save_election_config(self):
        """Lưu cấu hình bầu cử ra file JSON (dựa theo ID)."""
        self.clear_log()
        print("\n--- [AUTH] Bắt đầu lưu cấu hình bầu cử... ---")
        election_id = self.setup_election_id.get().strip()
        if not election_id:
            messagebox.showerror("Lỗi", "ID Bầu cử (tên file) không được để trống.")
            print("[ERROR] ID Bầu cử không được để trống.")
            return
        filename = f"{election_id}.json"
        config_path = config.ELECTIONS_DIR / filename
        try:
            positions_list = [p.strip() for p in self.setup_positions.get().split(',') if p.strip()]
            choices_list = [c.strip() for c in self.setup_choices.get().split(',') if c.strip()]
            if not positions_list or not choices_list:
                messagebox.showerror("Lỗi", "Vị trí và Ứng cử viên không được để trống.")
                print("[ERROR] Vị trí và Ứng cử viên không được để trống.")
                return
            config_data = {
                "display_name": election_id, 
                "positions": positions_list,
                "choices": choices_list
            }
            if config_path.exists():
                if not messagebox.askyesno("Xác nhận Ghi đè", 
                                           f"File '{filename}' đã tồn tại.\nBạn có muốn ghi đè lên nó không?"):
                    print("[INFO] Đã hủy lưu.")
                    return
                print(f"[INFO] Ghi đè lên file: {filename}")
            rabin.save_json(config_data, str(config_path)) 
            print(f"Đã lưu cấu hình vào: {config_path}")
            print(json.dumps(config_data, ensure_ascii=False, indent=2))
            print("--- [AUTH] Lưu cấu hình thành công! ---")
            messagebox.showinfo("Thành công", f"Đã lưu cấu hình bầu cử vào:\n{filename}")
            self.refresh_config_list()
        except Exception as e:
            print(f"\n[ERROR] Lỗi khi lưu cấuHình: {e}")
            messagebox.showerror("Lỗi", f"Có lỗi xảy ra: {e}")

    # --- (Hàm run_verify_all giữ nguyên) ---
    def run_verify_all(self):
        """Bước C: Xử lý TẤT CẢ file trong 'votes/'."""
        self.clear_log()
        print("--- [AUTH] Bước C: Bắt đầu kiểm tra tất cả phiếu MỚI... ---\n")
        auth_priv_path = config.get_authority_priv_path()
        votes_dir = config.VOTES_DIR
        if not auth_priv_path.exists():
            messagebox.showerror("Lỗi", f"Không tìm thấy khóa bí mật Authority:\n{auth_priv_path}\n"
                             "Vui lòng 'Sinh khóa Authority' trước.")
            print(f"[ERROR] Không tìm thấy {auth_priv_path}")
            return
        if not votes_dir.exists():
             votes_dir.mkdir(exist_ok=True)
        vote_files = list(votes_dir.glob("vote_*.json"))
        if not vote_files:
            print(f"[INFO] Thư mục '{votes_dir}' rỗng, không có phiếu nào để kiểm tra.")
            messagebox.showinfo("Thông báo", "Thư mục 'votes/' rỗng. Chưa có phiếu bầu mới.")
            return
        try:
            print(f"[INFO] Tìm thấy {len(vote_files)} phiếu mới. Bắt đầu xử lý...")
            valid_count = 0
            total_count = len(vote_files)
            for f_path in vote_files:
                if authority.authority_decrypt_and_verify(str(auth_priv_path), str(f_path)):
                    valid_count += 1
            print("\n--- [AUTH] Hoàn tất kiểm phiếu! ---")
            print(f"[SUMMARY] Đã xử lý: {total_count} phiếu. Hợp lệ: {valid_count}. Không hợp lệ: {total_count - valid_count}.")
        except Exception as e:
            print(f"\n[ERROR] Lỗi khi kiểm phiếu: {e}")
            messagebox.showerror("Lỗi", f"Có lỗi xảy ra: {e}")

    # --- HÀM CẬP NHẬT: run_show_results ---
    def run_show_results(self):
        """
        Bước D: Đọc file từ 'approved' và 'not_approved'
        VÀ LỌC KẾT QUẢ theo election đã chọn (tên sạch).
        """
        self.clear_log()
        
        # --- SỬA Ở ĐÂY ---
        # 1. Xác định ID bầu cử cần lọc
        
        # selected_name giờ là "lop-truong" (tên sạch), không còn ".json"
        selected_name = self.selected_results_election.get() 
        target_election_id = None # Mặc định là "TẤT CẢ"
        
        if selected_name and selected_name != "--- TẤT CẢ CUỘC BẦU CỬ ---":
            # Không cần dùng rsplit('.json') nữa!
            target_election_id = selected_name
        # --- HẾT SỬA ---
            
        
        if target_election_id:
            print(f"--- [AUTH] Đang tổng hợp kết quả cho: '{target_election_id}' ---")
        else:
            print("--- [AUTH] Đang tổng hợp kết quả cho: TẤT CẢ ---")
        
        approved_count = 0
        rejected_count = 0
        
        # 2. Xử lý phiếu HỢP LỆ (APPROVED)
        print("\n=== PHIẾU HỢP LỆ ===\n")
        config.APPROVED_DIR.mkdir(exist_ok=True) 
        approved_files = sorted(list(config.APPROVED_DIR.glob("*.json")))
        
        found_approved = 0
        for f in approved_files:
            try:
                with open(f, 'r', encoding='utf-8') as rf:
                    data = json.load(rf)
                
                # Lấy ID bầu cử của file này
                file_election_id = data.get('election_id')
                
                # BỘ LỌC (Logic này vẫn đúng)
                if target_election_id and file_election_id != target_election_id:
                    continue # Bỏ qua nếu không khớp
                
                # ... (Phần còn lại của hàm giữ nguyên) ...
                found_approved += 1
                ballot_id = data.get('ballot_id', f.name)
                position = data.get('positions', 'N/A')
                choice = data.get('choices', 'N/A')
                print(f"  [File]: {f.name} (Cuộc bầu cử: {file_election_id or 'N/A'})")
                print(f"  - ID Cử tri: {ballot_id}")
                print(f"  - Lựa chọn: [{position}] -> [{choice}]\n")
                    
            except Exception as e:
                print(f"[ERROR] Không thể đọc file kết quả {f.name}: {e}\n")
        
        if found_approved == 0:
            print("(Không có phiếu hợp lệ nào khớp với lựa chọn)")
        approved_count = found_approved

        # 3. Xử lý phiếu KHÔNG HỢP LỆ (NOT_APPROVED)
        print("\n=== PHIẾU BỊ TỪ CHỐI ===\n")
        config.NOT_APPROVED_DIR.mkdir(exist_ok=True) 
        rejected_files = sorted(list(config.NOT_APPROVED_DIR.glob("*.json")))

        found_rejected = 0
        for f in rejected_files:
            try:
                with open(f, 'r', encoding='utf-8') as rf:
                    data = json.load(rf)
                
                file_election_id = data.get('election_id')

                # BỘ LỌC (Logic này vẫn đúng)
                if target_election_id and file_election_id != target_election_id:
                    if file_election_id is None: 
                        continue
                    continue 
                
                found_rejected += 1
                reason = data.get('error', 'Lỗi không xác định')
                details = data.get('details', '')
                ballot_id = data.get('ballot_id') 
                if not ballot_id:
                    ballot_id = data.get('original_filename', f.name)
                
                print(f"  [File]: {f.name} (Cuộc bầu cử: {file_election_id or 'N/A'})")
                print(f"  - ID Cử tri: {ballot_id}")
                print(f"  - Lý do từ chối: {reason}")
                if details:
                    print(f"  - Chi tiết: {details}\n")
                else:
                    print("") 
                        
            except Exception as e:
                print(f"[ERROR] Không thể đọc file lỗi {f.name}: {e}\n")

        if found_rejected == 0:
            print("(Không có phiếu nào bị từ chối khớp với lựa chọn)")
        rejected_count = found_rejected

        # 4. In tổng kết (cho bộ lọc)
        print("\n" + "=" * 30)
        print(f"TỔNG KẾT (cho bộ lọc: {target_election_id or 'TẤT CẢ'})")
        print(f"  Phiếu hợp lệ: {approved_count}")
        print(f"  Phiếu bị từ chối: {rejected_count}")
        print(f"  TỔNG CỘNG: {approved_count + rejected_count}")
        print("=" * 30)


if __name__ == "__main__":
    # ... (Giữ nguyên) ...
    config.ensure_structure()
    root = tk.Tk()
    app = AuthorityApp(root)
    def on_closing():
        sys.stdout = sys.__stdout__
        root.destroy()
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()