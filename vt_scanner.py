import os
import csv
import hashlib
import time
import requests
import threading
import customtkinter as ctk
from tkinter import filedialog, messagebox

# Настройка внешнего вида
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class VirusTotalScannerApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("VirusTotal Folder Scanner")
        self.geometry("700x600")
        self.resizable(False, False)

        self.api_key = ctk.StringVar()
        self.folder_path = ctk.StringVar()
        
        # Список для хранения результатов сканирования (для CSV)
        self.scan_results = []

        # === Интерфейс ===
        
        # Заголовок
        self.label_title = ctk.CTkLabel(self, text="VirusTotal Folder Scanner", font=ctk.CTkFont(size=22, weight="bold"))
        self.label_title.pack(pady=(15, 10))

        # Поле ввода API ключа
        self.frame_api = ctk.CTkFrame(self)
        self.frame_api.pack(fill="x", padx=20, pady=5)

        self.label_api = ctk.CTkLabel(self.frame_api, text="API Key:", font=ctk.CTkFont(size=13))
        self.label_api.pack(side="left", padx=10)

        self.entry_api = ctk.CTkEntry(self.frame_api, textvariable=self.api_key, show="*", width=450, placeholder_text="Вставьте ваш VirusTotal API Key")
        self.entry_api.pack(side="left", padx=10, pady=10, fill="x", expand=True)

        # Выбор папки
        self.frame_folder = ctk.CTkFrame(self)
        self.frame_folder.pack(fill="x", padx=20, pady=5)

        self.btn_select_folder = ctk.CTkButton(self.frame_folder, text="Выбрать папку", command=self.select_folder, width=120)
        self.btn_select_folder.pack(side="left", padx=10, pady=10)

        self.entry_folder = ctk.CTkEntry(self.frame_folder, textvariable=self.folder_path, width=450, placeholder_text="Путь к папке")
        self.entry_folder.pack(side="left", padx=10, fill="x", expand=True)

        # Кнопки управления (Запуск + Экспорт)
        self.frame_actions = ctk.CTkFrame(self, fg_color="transparent")
        self.frame_actions.pack(fill="x", padx=20, pady=10)

        self.btn_start = ctk.CTkButton(self.frame_actions, text="Начать сканирование", command=self.start_scan_thread, font=ctk.CTkFont(size=14, weight="bold"), height=38, fg_color="#2FA572", hover_color="#1E6B4A")
        self.btn_start.pack(side="left", fill="x", expand=True, padx=(0, 5))

        self.btn_export = ctk.CTkButton(self.frame_actions, text="Сохранить в CSV", command=self.export_to_csv, font=ctk.CTkFont(size=13), height=38, fg_color="#3B8ED0", state="disabled")
        self.btn_export.pack(side="right", padx=(5, 0))

        # Прогресс-бар и статус
        self.progress = ctk.CTkProgressBar(self, orientation="horizontal")
        self.progress.pack(fill="x", padx=20, pady=(5, 5))
        self.progress.set(0)

        self.label_status = ctk.CTkLabel(self, text="Готов к работе", font=ctk.CTkFont(size=12))
        self.label_status.pack(pady=(0, 5))

        # Окно логов/результатов
        self.log_textbox = ctk.CTkTextbox(self, width=660, height=230, font=ctk.CTkFont(family="Consolas", size=12))
        self.log_textbox.pack(padx=20, pady=(0, 15))

    def select_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.folder_path.set(folder)

    def log(self, message):
        self.log_textbox.insert("end", message + "\n")
        self.log_textbox.see("end")

    def get_file_hash(self, file_path):
        hasher = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return None

    def start_scan_thread(self):
        if not self.api_key.get().strip():
            messagebox.showerror("Ошибка", "Введите API-ключ VirusTotal!")
            return
        if not self.folder_path.get().strip():
            messagebox.showerror("Ошибка", "Выберите папку для сканирования!")
            return

        self.btn_start.configure(state="disabled")
        self.btn_select_folder.configure(state="disabled")
        self.btn_export.configure(state="disabled")
        self.log_textbox.delete("1.0", "end")
        self.scan_results.clear()
        
        threading.Thread(target=self.scan_process, daemon=True).start()

    def scan_process(self):
        api_key = self.api_key.get().strip()
        folder = self.folder_path.get().strip()

        file_list = []
        for root, _, files in os.walk(folder):
            for file in files:
                file_list.append(os.path.join(root, file))

        total_files = len(file_list)
        if total_files == 0:
            self.log("[!] В выбранной папке нет файлов.")
            self.reset_ui()
            return

        self.log(f"[*] Найдено файлов: {total_files}\n" + "="*50)
        headers = {"x-apikey": api_key}

        for idx, file_path in enumerate(file_list, start=1):
            file_name = os.path.basename(file_path)
            self.label_status.configure(text=f"Сканирование [{idx}/{total_files}]: {file_name}")
            self.progress.set(idx / total_files)

            file_hash = self.get_file_hash(file_path)
            if not file_hash:
                self.log(f"[ОШИБКА ЧТЕНИЯ] {file_name}")
                self.scan_results.append({
                    "FileName": file_name, "Path": file_path, "Status": "Error Reading", "Malicious": 0, "SHA256": "N/A"
                })
                continue

            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            try:
                response = requests.get(url, headers=headers)
                
                if response.status_code == 200:
                    data = response.json()
                    stats = data['data']['attributes']['last_analysis_stats']
                    malicious = stats['malicious']
                    
                    status_str = f"Malicious ({malicious})" if malicious > 0 else "Clean"
                    if malicious > 0:
                        self.log(f"[ОПАСНО: {malicious}] {file_name}")
                    else:
                        self.log(f"[ЧИСТО] {file_name}")

                    self.scan_results.append({
                        "FileName": file_name, "Path": file_path, "Status": status_str, "Malicious": malicious, "SHA256": file_hash
                    })

                elif response.status_code == 404:
                    self.log(f"[НЕ НАЙДЕН В БАЗЕ] {file_name}")
                    self.scan_results.append({
                        "FileName": file_name, "Path": file_path, "Status": "Not Found", "Malicious": 0, "SHA256": file_hash
                    })
                elif response.status_code == 429:
                    self.log(f"[ЛИМИТ API] Превышен лимит. Ожидание 60 секунд...")
                    time.sleep(60)
                else:
                    self.log(f"[ОШИБКА API {response.status_code}] {file_name}")
                    self.scan_results.append({
                        "FileName": file_name, "Path": file_path, "Status": f"API Error {response.status_code}", "Malicious": 0, "SHA256": file_hash
                    })

            except Exception as e:
                self.log(f"[СБОЙ СЕТИ] {file_name}: {e}")

            if idx < total_files:
                time.sleep(15)

        self.log("\n" + "="*50 + "\n[*] Сканирование завершено!")
        self.label_status.configure(text="Сканирование завершено")
        self.reset_ui()

    def reset_ui(self):
        self.btn_start.configure(state="normal")
        self.btn_select_folder.configure(state="normal")
        if len(self.scan_results) > 0:
            self.btn_export.configure(state="normal")

    def export_to_csv(self):
        """Экспорт собранных результатов в CSV файл"""
        if not self.scan_results:
            messagebox.showwarning("Предупреждение", "Нет данных для экспорта!")
            return

        save_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            title="Сохранить отчет как..."
        )

        if save_path:
            try:
                with open(save_path, mode='w', newline='', encoding='utf-8-sig') as file:
                    writer = csv.DictWriter(file, fieldnames=["FileName", "Path", "Status", "Malicious", "SHA256"])
                    writer.writeheader()
                    writer.writerows(self.scan_results)
                messagebox.showinfo("Успех", f"Отчет успешно сохранен в:\n{save_path}")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось сохранить файл: {e}")

if __name__ == "__main__":
    app = VirusTotalScannerApp()
    app.mainloop()