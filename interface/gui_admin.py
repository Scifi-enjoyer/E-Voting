"""
gui_admin.py
Giao diện System Admin - Chỉ dùng để theo dõi sức khỏe hệ thống.
Không có quyền xem nội dung phiếu.
"""
import tkinter as tk
from tkinter import ttk
import sys, os

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(project_root)

import src.db_manager as db

class SystemAdminApp:
    def __init__(self, root):
        self.root = root
        self.root.title("System Admin Dashboard (Giám sát Hệ thống)")
        self.root.geometry("400x300")
        
        tk.Label(root, text="BẢNG ĐIỀU KHIỂN HỆ THỐNG", font=("Arial", 14, "bold"), fg="red").pack(pady=15)
        
        self.stats_frame = tk.Frame(root)
        self.stats_frame.pack(pady=10)
        
        self.lbl_users = tk.Label(self.stats_frame, text="Tổng User: 0 (Đang online: 0)", font=("Arial", 11))
        self.lbl_users.pack(anchor="w", pady=5)
        
        self.lbl_elections = tk.Label(self.stats_frame, text="Tổng số phòng bỏ phiếu: 0", font=("Arial", 11))
        self.lbl_elections.pack(anchor="w", pady=5)
        
        self.lbl_votes = tk.Label(self.stats_frame, text="Tổng số phiếu đã gửi: 0", font=("Arial", 11))
        self.lbl_votes.pack(anchor="w", pady=5)
        
        tk.Button(root, text="🔄 Cập nhật số liệu", bg="#1976D2", fg="white", 
                  command=self.refresh_stats).pack(pady=20)
        
        self.refresh_stats()

    def refresh_stats(self):
        stats = db.get_admin_stats()
        if stats:
            self.lbl_users.config(text=f"Tổng User: {stats['total_users']} (Đang online: {stats['online_users']})")
            self.lbl_elections.config(text=f"Tổng số phòng bỏ phiếu: {stats['total_elections']}")
            self.lbl_votes.config(text=f"Tổng số phiếu đã gửi trên DB: {stats['total_votes']}")

if __name__ == "__main__":
    root = tk.Tk()
    app = SystemAdminApp(root)
    root.mainloop()