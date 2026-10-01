# ==============================================================================
# Проект: VirusTotal Multi-Folder Scanner (GUI)
# Версия: 2.0
# Описание: Сканер папок на VirusTotal с сохранением ключа и выбором нескольких папок.
# ==============================================================================

import builtins
import os
import csv
import json
import sqlite3
import hashlib
import time
import requests
import threading
import webbrowser
from tkinter import filedialog, messagebox, ttk
import customtkinter as ctk

# Настройки внешнего вида CustomTkinter
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

CONFIG_FILE = "config.json"
CACHE_DB = "vt_cache.db"

# ==============================================================================
# СЛОВАРЬ ЛОКАЛИЗАЦИИ / TRANSLATIONS DICTIONARY
# ==============================================================================
TRANSLATIONS = {
    "ru": {
        "title": "VirusTotal Multi-Folder Scanner",
        "api_title": "API-ключ VirusTotal:",
        "api_placeholder": "Вставьте API-ключ сюда...",
        "get_key": "🔑 Нет ключа? Нажмите сюда, чтобы получить его на VirusTotal",
        "filter_exec": "Только исполняемые (.exe, .dll, .sys, .bat, .ps1, .msi)",
        "max_size": "Макс. размер (МБ):",
        "folders_title": "Папки для сканирования:",
        "no_folders": "Папки не выбраны...",
        "btn_add_f": "➕ Добавить папку",
        "btn_clear_f": "🗑️ Очистить список",
        "btn_start": "🚀 Начать сканирование",
        "btn_pause": "⏸ Пауза",
        "btn_resume": "▶ Продолжить",
        "btn_stop": "⏹ Стоп",
        "col_file": "Имя файла",
        "col_status": "Статус",
        "col_detections": "Детекты",
        "col_hash": "SHA-256",
        "status_ready": "Готов к работе",
        "status_paused": "Сканирование приостановлено",
        "status_stopping": "Остановка сканирования...",
        "status_done": "Сканирование завершено!",
        "status_stopped": "Сканирование остановлено.",
        "status_empty": "Подходящие файлы не найдены.",
        "status_checking": "Проверка: ",
        "status_limit": "Превышен лимит API (4 зап/мин). Ожидание 15 сек...",
        "status_clean": "🟢 Чисто",
        "status_malicious": "🔴 Опасно",
        "status_not_found": "⚪ Не найден",
        "status_read_error": "Ошибка чтения",
        "status_limit_error": "Лимит запросов",
        "status_net_error": "Ошибка сети",
        "btn_export": "💾 Сохранить отчет в CSV",
        "err_no_api": "Укажите VirusTotal API Key!",
        "err_no_folders": "Добавьте хотя бы одну папку для сканирования!",
        "err_title": "Ошибка",
        "success_title": "Успех",
        "success_export": "Отчет успешно сохранен!"
    },
    "en": {
        "title": "VirusTotal Multi-Folder Scanner",
        "api_title": "VirusTotal API Key:",
        "api_placeholder": "Paste your API key here...",
        "get_key": "🔑 Don't have a key? Click here to get one on VirusTotal",
        "filter_exec": "Only executables (.exe, .dll, .sys, .bat, .ps1, .msi)",
        "max_size": "Max size (MB):",
        "folders_title": "Folders to scan:",
        "no_folders": "No folders selected...",
        "btn_add_f": "➕ Add Folder",
        "btn_clear_f": "🗑️ Clear List",
        "btn_start": "🚀 Start Scan",
        "btn_pause": "⏸ Pause",
        "btn_resume": "▶ Resume",
        "btn_stop": "⏹ Stop",
        "col_file": "File Name",
        "col_status": "Status",
        "col_detections": "Detections",
        "col_hash": "SHA-256",
        "status_ready": "Ready",
        "status_paused": "Scan paused",
        "status_stopping": "Stopping scan...",
        "status_done": "Scanning completed!",
        "status_stopped": "Scanning stopped.",
        "status_empty": "No matching files found.",
        "status_checking": "Checking: ",
        "status_limit": "API limit exceeded (4 req/min). Waiting 15s...",
        "status_clean": "🟢 Clean",
        "status_malicious": "🔴 Malicious",
        "status_not_found": "⚪ Not Found",
        "status_read_error": "Read Error",
        "status_limit_error": "Rate Limit",
        "status_net_error": "Network Error",
        "btn_export": "💾 Save CSV Report",
        "err_no_api": "Please specify a VirusTotal API Key!",
        "err_no_folders": "Please add at least one folder to scan!",
        "err_title": "Error",
        "success_title": "Success",
        "success_export": "Report saved successfully!"
    }
}

class LanguageSelectionDialog(ctk.CTkToplevel):
    """Диалог первого запуска для выбора языка."""
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Language / Язык")
        self.geometry("320x160")
        self.resizable(False, False)
        self.selected_lang = "ru"
        
        self.transient(parent)
        self.grab_set()

        lbl = ctk.CTkLabel(self, text="Выберите язык / Select Language:", font=ctk.CTkFont(size=14, weight="bold"))
        lbl.pack(pady=(20, 15))

        btn_ru = ctk.CTkButton(self, text="Русский 🇷🇺", command=lambda: self.set_lang("ru"))
        btn_ru.pack(side="left", padx=20, expand=True)

        btn_en = ctk.CTkButton(self, text="English 🇬🇧", command=lambda: self.set_lang("en"))
        btn_en.pack(side="right", padx=20, expand=True)

        self.protocol("WM_DELETE_WINDOW", lambda: self.set_lang("ru"))
        self.wait_window()

    def set_lang(self, lang):
        self.selected_lang = lang
        self.destroy()

class CacheManager:
    """Управление локальной базой данных SQLite для кэширования хешей."""
    def __init__(self, db_path=CACHE_DB):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS cache (
                    sha256 TEXT PRIMARY KEY,
                    status TEXT,
                    detections TEXT,
                    last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            conn.commit()

    def get(self, sha256):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT status, detections FROM cache WHERE sha256 = ?", (sha256,))
            return cursor.fetchone()

    def set(self, sha256, status, detections):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO cache (sha256, status, detections)
                VALUES (?, ?, ?)
            ''', (sha256, status, detections))
            conn.commit()

class VirusTotalScannerApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.cache = CacheManager()
        self.selected_folders = []
        self.scan_results = []
        
        # Флаги управления потоком
        self.is_scanning = False
        self.is_paused = False
        self.stop_requested = False

        # Загрузка настроек и проверка первого запуска
        self.lang = "ru"
        self.api_key_initial = ""
        self.check_first_launch()

        self.title("VirusTotal Folder Scanner v2.0")
        self.geometry("900x840")
        self.resizable(True, True)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self._build_ui()
        self.apply_language()

        if self.api_key_initial:
            self.entry_api.insert(0, self.api_key_initial)

    def on_close(self):
        """Сохранить настройки и корректно закрыть приложение."""
        self.save_config()
        self.destroy()

    def tr(self, key):
        """Получить переведенный текст по ключу."""
        return TRANSLATIONS[self.lang].get(key, key)

    def check_first_launch(self):
        """Проверка наличия config.json. Если нет — показываем диалог выбора языка."""
        if not os.path.exists(CONFIG_FILE):
            dialog = LanguageSelectionDialog(self)
            self.lang = dialog.selected_lang
            self.save_config()
        else:
            try:
                with builtins.open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.lang = data.get("language", "ru")
                    self.api_key_initial = data.get("api_key", "")
            except Exception:
                self.lang = "ru"

    def _build_ui(self):
        # Header + Language Switcher
        self.frame_top = ctk.CTkFrame(self, fg_color="transparent")
        self.frame_top.pack(fill="x", padx=15, pady=(10, 0))

        self.label_title = ctk.CTkLabel(self.frame_top, text="", font=ctk.CTkFont(size=20, weight="bold"))
        self.label_title.pack(side="left")

        # Переключатель языка
        self.segmented_lang = ctk.CTkSegmentedButton(
            self.frame_top, 
            values=["RU 🇷🇺", "EN 🇬🇧"], 
            command=self.on_lang_change
        )
        self.segmented_lang.set("RU 🇷🇺" if self.lang == "ru" else "EN 🇬🇧")
        self.segmented_lang.pack(side="right")

        # API & Settings Frame
        self.frame_api = ctk.CTkFrame(self)
        self.frame_api.pack(fill="x", padx=15, pady=10)

        self.lbl_api = ctk.CTkLabel(self.frame_api, text="", font=ctk.CTkFont(weight="bold"))
        self.lbl_api.pack(anchor="w", padx=10, pady=(5, 0))

        self.entry_api = ctk.CTkEntry(self.frame_api, placeholder_text="", show="*")
        self.entry_api.pack(fill="x", padx=10, pady=5)

        self.lbl_link = ctk.CTkLabel(
            self.frame_api, 
            text="", 
            font=ctk.CTkFont(size=12, underline=True),
            cursor="hand2",
            text_color="#1E90FF"
        )
        self.lbl_link.pack(anchor="w", padx=10, pady=(0, 5))
        # Исправлено: добавлен 
        self.lbl_link.bind("<Button-1>", lambda e: webbrowser.open("https://www.virustotal.com/gui/my-apikey"))

        # Filters Frame
        self.frame_opts = ctk.CTkFrame(self.frame_api, fg_color="transparent")
        self.frame_opts.pack(fill="x", padx=10, pady=5)

        self.chk_exec_only = ctk.CTkCheckBox(self.frame_opts, text="")
        self.chk_exec_only.pack(side="left", padx=(0, 15))
        self.chk_exec_only.select()

        self.lbl_max_size = ctk.CTkLabel(self.frame_opts, text="")
        self.lbl_max_size.pack(side="left", padx=(0, 5))
        
        self.entry_max_size = ctk.CTkEntry(self.frame_opts, width=60)
        self.entry_max_size.insert(0, "65")
        self.entry_max_size.pack(side="left")

        # Folder Selection Frame
        self.frame_folders = ctk.CTkFrame(self)
        self.frame_folders.pack(fill="x", padx=15, pady=5)

        self.lbl_folders = ctk.CTkLabel(self.frame_folders, text="", font=ctk.CTkFont(weight="bold"))
        self.lbl_folders.pack(anchor="w", padx=10, pady=(5, 0))

        self.textbox_folders = ctk.CTkTextbox(self.frame_folders, height=60, state="disabled")
        self.textbox_folders.pack(fill="x", padx=10, pady=5)

        self.frame_f_btns = ctk.CTkFrame(self.frame_folders, fg_color="transparent")
        self.frame_f_btns.pack(fill="x", padx=10, pady=(0, 5))

        self.btn_add_f = ctk.CTkButton(self.frame_f_btns, text="", command=self.add_folder)
        self.btn_add_f.pack(side="left", padx=(0, 10))

        self.btn_clear_f = ctk.CTkButton(self.frame_f_btns, text="", fg_color="#D32F2F", hover_color="#9A0007", command=self.clear_folders)
        self.btn_clear_f.pack(side="left")

        # Controls Frame
        self.frame_controls = ctk.CTkFrame(self, fg_color="transparent")
        self.frame_controls.pack(fill="x", padx=15, pady=5)

        self.btn_start = ctk.CTkButton(self.frame_controls, text="", font=ctk.CTkFont(weight="bold"), command=self.start_scan)
        self.btn_start.pack(side="left", expand=True, fill="x", padx=(0, 5))

        self.btn_pause = ctk.CTkButton(self.frame_controls, text="", state="disabled", command=self.toggle_pause)
        self.btn_pause.pack(side="left", expand=True, fill="x", padx=5)

        self.btn_stop = ctk.CTkButton(self.frame_controls, text="", fg_color="#D32F2F", state="disabled", command=self.stop_scan)
        self.btn_stop.pack(side="left", expand=True, fill="x", padx=(5, 0))

        self.progress_bar = ctk.CTkProgressBar(self)
        self.progress_bar.pack(fill="x", padx=15, pady=5)
        self.progress_bar.set(0)

        # Interactive Results Table
        self.frame_table = ctk.CTkFrame(self)
        self.frame_table.pack(fill="both", expand=True, padx=15, pady=5)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#2b2b2b", foreground="white", fieldbackground="#2b2b2b", rowheight=25)
        style.map("Treeview", background=[("selected", "#1f538d")])

        self.tree = ttk.Treeview(self.frame_table, columns=("file", "status", "detections", "hash"), show="headings")
        self.tree.column("file", width=250)
        self.tree.column("status", width=150)
        self.tree.column("detections", width=100, anchor="center")
        self.tree.column("hash", width=250)

        self.tree.tag_configure("clean", foreground="#4CAF50")
        self.tree.tag_configure("malicious", foreground="#F44336")
        self.tree.tag_configure("not_found", foreground="#9E9E9E")
        self.tree.tag_configure("error", foreground="#FF9800")

        scrollbar = ttk.Scrollbar(self.frame_table, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.tree.pack(fill="both", expand=True)

        # Исправлено: добавлен 
        self.tree.bind("<Double-1>", self.on_row_double_click)

        # Bottom Bar
        self.frame_bottom = ctk.CTkFrame(self, fg_color="transparent")
        self.frame_bottom.pack(fill="x", padx=15, pady=(5, 10))

        self.lbl_status = ctk.CTkLabel(self.frame_bottom, text="")
        self.lbl_status.pack(side="left")

        self.btn_export = ctk.CTkButton(self.frame_bottom, text="", state="disabled", command=self.export_csv)
        self.btn_export.pack(side="right")

    def on_lang_change(self, choice):
        """Переключение языка через интерфейс."""
        self.lang = "ru" if choice == "RU 🇷🇺" else "en"
        self.save_config()
        self.apply_language()

    def apply_language(self):
        """Обновить тексты всех элементов UI под выбранный язык."""
        self.label_title.configure(text=self.tr("title"))
        self.lbl_api.configure(text=self.tr("api_title"))
        self.entry_api.configure(placeholder_text=self.tr("api_placeholder"))
        self.lbl_link.configure(text=self.tr("get_key"))
        self.chk_exec_only.configure(text=self.tr("filter_exec"))
        self.lbl_max_size.configure(text=self.tr("max_size"))
        self.lbl_folders.configure(text=self.tr("folders_title"))
        self.btn_add_f.configure(text=self.tr("btn_add_f"))
        self.btn_clear_f.configure(text=self.tr("btn_clear_f"))
        self.btn_start.configure(text=self.tr("btn_start"))
        self.btn_pause.configure(text=self.tr("btn_resume") if self.is_paused else self.tr("btn_pause"))
        self.btn_stop.configure(text=self.tr("btn_stop"))
        self.btn_export.configure(text=self.tr("btn_export"))
        
        self.tree.heading("file", text=self.tr("col_file"))
        self.tree.heading("status", text=self.tr("col_status"))
        self.tree.heading("detections", text=self.tr("col_detections"))
        self.tree.heading("hash", text=self.tr("col_hash"))

        if not self.is_scanning:
            self.lbl_status.configure(text=self.tr("status_ready"))

        self.update_folders_display()

    def save_config(self):
        """Сохранение API-ключа и языка в config.json."""
        try:
            data = {
                "api_key": self.entry_api.get().strip() if hasattr(self, 'entry_api') else self.api_key_initial,
                "language": self.lang
            }
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=4)
        except Exception:
            pass

    # Работа с папками
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
        text = "\n".join(self.selected_folders) if self.selected_folders else self.tr("no_folders")
        self.textbox_folders.insert("end", text)
        self.textbox_folders.configure(state="disabled")

    # Вспомогательные функции
    def get_file_hash(self, file_path):
        hasher = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return None

    def on_row_double_click(self, event):
        item = self.tree.selection()
        if not item:
            return
        file_hash = self.tree.item(item[0], "values")[3]
        if file_hash and len(file_hash) == 64:
            webbrowser.open(f"https://www.virustotal.com/gui/file/{file_hash}")

    def ui(self, callback, *args, **kwargs):
        """Безопасно выполнить изменение интерфейса в главном потоке Tkinter."""
        self.after(0, lambda: callback(*args, **kwargs))

    # Управление потоком
    def toggle_pause(self):
        self.is_paused = not self.is_paused
        self.btn_pause.configure(text=self.tr("btn_resume") if self.is_paused else self.tr("btn_pause"))
        self.lbl_status.configure(text=self.tr("status_paused") if self.is_paused else self.tr("status_ready"))

    def stop_scan(self):
        self.stop_requested = True
        self.lbl_status.configure(text=self.tr("status_stopping"))

    # Главный поток сканирования
    def start_scan(self):
        if not self.entry_api.get().strip():
            messagebox.showerror(self.tr("err_title"), self.tr("err_no_api"))
            return
        if not self.selected_folders:
            messagebox.showerror(self.tr("err_title"), self.tr("err_no_folders"))
            return

        self.save_config()
        self.is_scanning = True
        self.is_paused = False
        self.stop_requested = False

        self.btn_start.configure(state="disabled")
        self.btn_pause.configure(state="normal", text=self.tr("btn_pause"))
        self.btn_stop.configure(state="normal")
        self.btn_export.configure(state="disabled")

        for row in self.tree.get_children():
            self.tree.delete(row)
        self.scan_results.clear()

        threading.Thread(target=self.scan_process, daemon=True).start()

    def scan_process(self):
        api_key = self.entry_api.get().strip()
        exec_only = self.chk_exec_only.get()
        try:
            max_size_mb = float(self.entry_max_size.get())
        except ValueError:
            max_size_mb = 65.0

        valid_exts = {'.exe', '.dll', '.sys', '.bat', '.ps1', '.vbs', '.msi', '.cmd'}

        # Сбор и фильтрация файлов
        files_to_scan = []
        for folder in self.selected_folders:
            for root, _, files in os.walk(folder):
                for file in files:
                    ext = os.path.splitext(file)[1].lower()
                    if exec_only and ext not in valid_exts:
                        continue
                    
                    full_path = os.path.join(root, file)
                    if os.path.getsize(full_path) > (max_size_mb * 1024 * 1024):
                        continue
                        
                    files_to_scan.append(full_path)

        total_files = len(files_to_scan)
        if total_files == 0:
            self.ui(self.lbl_status.configure, text=self.tr("status_empty"))
            self.after(0, self.reset_controls)
            return

        headers = {"x-apikey": api_key}
        url = "https://www.virustotal.com/api/v3/files/"

        for index, file_path in enumerate(files_to_scan, start=1):
            if self.stop_requested:
                break

            while self.is_paused:
                time.sleep(0.5)
                if self.stop_requested:
                    break

            file_name = os.path.basename(file_path)
            self.ui(self.lbl_status.configure, text=f'[{index}/{total_files}] {self.tr("status_checking")}{file_name}')

            file_hash = self.get_file_hash(file_path)
            if not file_hash:
                self.ui(self.add_table_row, file_name, self.tr("status_read_error"), "-", "-", "error", file_path)
                continue

            # 1. Проверка в кэше
            cached_res = self.cache.get(file_hash)
            if cached_res:
                status, detections = cached_res
                tag = "malicious" if "Опасно" in status or "Malicious" in status else ("clean" if "Чисто" in status or "Clean" in status else "not_found")
                self.ui(self.add_table_row, file_name, f"⚡ {status} (Cache)", detections, file_hash, tag, file_path)
                self.ui(self.progress_bar.set, index / total_files)
                continue

            # 2. Запрос к VirusTotal API
            try:
                response = requests.get(url + file_hash, headers=headers, timeout=30)
                
                if response.status_code == 200:
                    stats = response.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                    malicious = stats.get('malicious', 0)
                    total = sum(stats.values())
                    
                    status = self.tr("status_malicious") if malicious > 0 else self.tr("status_clean")
                    detections = f"{malicious}/{total}"
                    tag = "malicious" if malicious > 0 else "clean"
                    
                    self.cache.set(file_hash, status, detections)
                    self.ui(self.add_table_row, file_name, status, detections, file_hash, tag, file_path)

                elif response.status_code == 404:
                    status = self.tr("status_not_found")
                    detections = "-"
                    self.cache.set(file_hash, status, detections)
                    self.ui(self.add_table_row, file_name, status, detections, file_hash, "not_found", file_path)

                elif response.status_code == 429:
                    self.ui(self.lbl_status.configure, text=self.tr("status_limit"))
                    time.sleep(15)
                    response = requests.get(url + file_hash, headers=headers, timeout=30)
                    if response.status_code == 200:
                        stats = response.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                        malicious = stats.get('malicious', 0)
                        total = sum(stats.values())
                        status = self.tr("status_malicious") if malicious > 0 else self.tr("status_clean")
                        detections = f"{malicious}/{total}"
                        tag = "malicious" if malicious > 0 else "clean"
                        self.cache.set(file_hash, status, detections)
                        self.ui(self.add_table_row, file_name, status, detections, file_hash, tag, file_path)
                    else:
                        self.ui(self.add_table_row, file_name, self.tr("status_limit_error"), "-", file_hash, "error", file_path)

                else:
                    self.ui(self.add_table_row, file_name, f"Error {response.status_code}", "-", file_hash, "error", file_path)

            except Exception:
                self.ui(self.add_table_row, file_name, self.tr("status_net_error"), "-", file_hash, "error", file_path)

            self.ui(self.progress_bar.set, index / total_files)
            time.sleep(15)

        self.ui(self.lbl_status.configure, text=self.tr("status_stopped") if self.stop_requested else self.tr("status_done"))
        self.after(0, self.reset_controls)

    def add_table_row(self, name, status, detections, file_hash, tag, full_path):
        self.tree.insert("", "end", values=(name, status, detections, file_hash), tags=(tag,))
        self.scan_results.append([name, full_path, status, detections, file_hash])

    def reset_controls(self):
        self.is_scanning = False
        self.btn_start.configure(state="normal")
        self.btn_pause.configure(state="disabled")
        self.btn_stop.configure(state="disabled")
        if self.scan_results:
            self.btn_export.configure(state="normal")

    # Экспорт в CSV
    def export_csv(self):
        save_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if save_path:
            try:
                with open(save_path, mode='w', newline='', encoding='utf-8-sig') as f:
                    writer = csv.writer(f, delimiter=';')
                    writer.writerow([self.tr("col_file"), "Path", self.tr("col_status"), self.tr("col_detections"), self.tr("col_hash")])
                    writer.writerows(self.scan_results)
                messagebox.showinfo(self.tr("success_title"), self.tr("success_export"))
            except Exception as e:
                messagebox.showerror(self.tr("err_title"), f"Save error: {e}")

if __name__ == "__main__":
    app = VirusTotalScannerApp()
    app.mainloop()
