# ==============================================================================
# Проект: VirusTotal Multi-Folder Scanner (GUI)
# Версия: 1.1
# Описание: Сканер папок на VirusTotal с сохранением ключа и выбором нескольких папок.
# ==============================================================================

import os
import csv
import json
import hashlib
import time
import requests
import threading
import webbrowser
import customtkinter as ctk
from tkinter import filedialog, messagebox

# Настройки оформления
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

CONFIG_FILE = "config.json"

class VirusTotalScannerApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("VirusTotal Folder Scanner v1.1")
        self.geometry("700x720")
        self.resizable(False, False)

        # Переменные
        self.selected_folders = [] # Список выбранных папок
        self.scan_results = []     # Результаты для экспорта в CSV

        # --- ГЛАВНЫЙ ЗАГОЛОВОК ---
        self.label_title = ctk.CTkLabel(
            self, 
            text="VirusTotal Multi-Folder Scanner", 
            font=ctk.CTkFont(size=22, weight="bold")
        )
        self.label_title.pack(pady=(15, 5))

        # --- БЛОК 1: API КЛЮЧ ---
        self.frame_api = ctk.CTkFrame(self)
        self.frame_api.pack(fill="x", padx=20, pady=10)

        self.lbl_api = ctk.CTkLabel(self.frame_api, text="API Key VirusTotal:", font=ctk.CTkFont(weight="bold"))
        self.lbl_api.pack(anchor="w", padx=15, pady=(10, 2))

        self.entry_api = ctk.CTkEntry(self.frame_api, placeholder_text="Вставьте ваш API-ключ сюда...", show="*")
        self.entry_api.pack(fill="x", padx=15, pady=5)

        # Ссылка на получение ключа
        self.lbl_link = ctk.CTkLabel(
            self.frame_api, 
            text="🔑 Нет ключа? Нажмите сюда, чтобы получить его на VirusTotal", 
            font=ctk.CTkFont(size=12, underline=True),
            cursor="hand2",
            text_color="#1E90FF"
        )
        self.lbl_link.pack(anchor="w", padx=15, pady=(0, 10))
        self.lbl_link.bind("<Button-1>", lambda e: webbrowser.open("https://www.virustotal.com/gui/my-apikey"))

        # --- БЛОК 2: ВЫБОР ПАПОК ---
        self.frame_folders = ctk.CTkFrame(self)
        self.frame_folders.pack(fill="x", padx=20, pady=5)

        self.lbl_folders = ctk.CTkLabel(self.frame_folders, text="Папки для сканирования:", font=ctk.CTkFont(weight="bold"))
        self.lbl_folders.pack(anchor="w", padx=15, pady=(10, 5))

        # Текстовое поле со списком добавленных папок
        self.textbox_folders = ctk.CTkTextbox(self.frame_folders, height=80, state="disabled")
        self.textbox_folders.pack(fill="x", padx=15, pady=5)

        # Кнопки добавления и очистки папок
        self.frame_folder_btns = ctk.CTkFrame(self.frame_folders, fg_color="transparent")
        self.frame_folder_btns.pack(fill="x", padx=15, pady=(0, 10))

        self.btn_add_folder = ctk.CTkButton(self.frame_folder_btns, text="➕ Добавить папку", command=self.add_folder)
        self.btn_add_folder.pack(side="left", padx=(0, 10))

        self.btn_clear_folders = ctk.CTkButton(self.frame_folder_btns, text="🗑️ Очистить список", fg_color="#D32F2F", hover_color="#9A0007", command=self.clear_folders)
        self.btn_clear_folders.pack(side="left")

        # --- БЛОК 3: УПРАВЛЕНИЕ И ПРОГРЕСС ---
        self.btn_start = ctk.CTkButton(self, text="🚀 Начать сканирование", font=ctk.CTkFont(size=15, weight="bold"), height=40, command=self.start_scan_thread)
        self.btn_start.pack(fill="x", padx=20, pady=10)

        self.progress_bar = ctk.CTkProgressBar(self)
        self.progress_bar.pack(fill="x", padx=20, pady=5)
        self.progress_bar.set(0)

        # --- БЛОК 4: ЛОГ И РЕЗУЛЬТАТЫ ---
        self.textbox_log = ctk.CTkTextbox(self, height=180)
        self.textbox_log.pack(fill="both", expand=True, padx=20, pady=10)

        self.btn_export = ctk.CTkButton(self, text="💾 Сохранить отчет в CSV", state="disabled", command=self.export_csv)
        self.btn_export.pack(padx=20, pady=(0, 15))

        # Загружаем сохраненный ключ при запуске
        self.load_api_key()

    # --- ЛОГИКА СОХРАНЕНИЯ / ЗАГРУЗКИ КЛЮЧА ---
    def load_api_key(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    saved_key = data.get("api_key", "")
                    if saved_key:
                        self.entry_api.insert(0, saved_key)
            except Exception:
                pass

    def save_api_key(self, key):
        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump({"api_key": key}, f)
        except Exception:
            pass

    # --- РАБОТА С ПАПКАМИ ---
    def add_folder(self):
        folder = filedialog.askdirectory()
        if folder and folder not in self.selected_folders:
            self.selected_folders.append(folder)
            self.update_folders_display()

    def clear_folders(self):
        self.selected_folders.clear()
        self.update_folders_display()

    def update_folders_display(self):
        self.textbox_folders.configure(state="normal")
        self.textbox_folders.delete("1.0", "end")
        if self.selected_folders:
            for f in self.selected_folders:
                self.textbox_folders.insert("end", f"{f}\n")
        else:
            self.textbox_folders.insert("end", "Папки не выбраны...")
        self.textbox_folders.configure(state="disabled")

    # --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ---
    def log(self, message):
        self.textbox_log.insert("end", message + "\n")
        self.textbox_log.see("end")

    def get_file_hash(self, file_path):
        hasher = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return None

    # --- СКАНИРОВАНИЕ ---
    def start_scan_thread(self):
        threading.Thread(target=self.scan_process, daemon=True).start()

    def scan_process(self):
        api_key = self.entry_api.get().strip()

        if not api_key:
            messagebox.showerror("Ошибка", "Укажите VirusTotal API Key!")
            return

        if not self.selected_folders:
            messagebox.showerror("Ошибка", "Добавьте хотя бы одну папку для сканирования!")
            return

        # Сохраняем ключ для будущих запусков
        self.save_api_key(api_key)

        self.btn_start.configure(state="disabled")
        self.btn_export.configure(state="disabled")
        self.textbox_log.delete("1.0", "end")
        self.scan_results.clear()

        # Собираем все файлы со всех выбранных папок
        files_to_scan = []
        for folder in self.selected_folders:
            for root, _, files in os.walk(folder):
                for file in files:
                    files_to_scan.append(os.path.join(root, file))

        total_files = len(files_to_scan)
        if total_files == 0:
            self.log("⚠️ Выбранные папки пусты.")
            self.btn_start.configure(state="normal")
            return

        self.log(f"🔍 Найдено файлов для проверки: {total_files}\n" + "-"*40)

        url = "https://www.virustotal.com/api/v3/files/"
        headers = {"x-apikey": api_key}

        for index, file_path in enumerate(files_to_scan, start=1):
            file_name = os.path.basename(file_path)
            self.log(f"[{index}/{total_files}] Проверка: {file_name}")

            file_hash = self.get_file_hash(file_path)
            if not file_hash:
                self.log("  ❌ Ошибка чтения файла (нет доступа).")
                self.scan_results.append([file_name, file_path, "Ошибка чтения", "-"])
                continue

            try:
                response = requests.get(url + file_hash, headers=headers)
                if response.status_code == 200:
                    data = response.json()
                    stats = data['data']['attributes']['last_analysis_stats']
                    malicious = stats.get('malicious', 0)
                    total = sum(stats.values())
                    status = f"🔴 Опасно ({malicious}/{total})" if malicious > 0 else "🟢 Чисто"
                    self.log(f"  Результат: {status}")
                    self.scan_results.append([file_name, file_path, status, f"{malicious}/{total}"])
                elif response.status_code == 404:
                    self.log("  ⚪ Файл не найден в базе VirusTotal.")
                    self.scan_results.append([file_name, file_path, "Не найден в базе", "-"])
                elif response.status_code == 429:
                    self.log("  ⚠️ Превышен лимит API (4 запроса в мин). Ждем 15 сек...")
                    time.sleep(15)
                else:
                    self.log(f"  ❌ Ошибка API: {response.status_code}")
                    self.scan_results.append([file_name, file_path, f"Ошибка {response.status_code}", "-"])
            except Exception as e:
                self.log(f"  ❌ Ошибка сети: {e}")

            self.progress_bar.set(index / total_files)
            time.sleep(15) # Пауза для бесплатного API (4 запроса в минуту)

        self.log("\n✅ Сканирование завершено!")
        self.btn_start.configure(state="normal")
        if self.scan_results:
            self.btn_export.configure(state="normal")

    def export_csv(self):
        save_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if save_path:
            try:
                with open(save_path, mode='w', newline='', encoding='utf-8-sig') as f:
                    writer = csv.writer(f, delimiter=';')
                    writer.writerow(["Имя файла", "Полный путь", "Статус", "Детекты"])
                    writer.writerows(self.scan_results)
                messagebox.showinfo("Успех", "Отчет успешно сохранен!")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось сохранить файл: {e}")

if __name__ == "__main__":
    app = VirusTotalScannerApp()
    app.mainloop()