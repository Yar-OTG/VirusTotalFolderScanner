## 🛡️ VirusTotal Folder Scanner (GUI)

Desktop-приложение на Python для массовой проверки файлов в выбранной папке на вредоносное ПО с использованием официального **VirusTotal API v3**.

![Python](https://img.shields.io/badge/Python-3.x-blue.svg)
![CustomTkinter](https://img.shields.io/badge/UI-CustomTkinter-blueviolet.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

---

## 🚀 Основные возможности

* 📁 **Сканирование папок:** Автоматический рекурсивный обход всех файлов и подпапок.
* ⚡ **Проверка по SHA-256:** Мгновенный запрос к базе VirusTotal без необходимости загружать сам файл.
* 📊 **Экспорт отчетов:** Сохранение результатов сканирования в `.csv` файл (совместим с Excel).
* 🧵 **Многопоточность (Multi-threading):** Интерфейс не зависает во время выполнения сетевых запросов.
* 🎨 **Современный UI:** Темная тема в стиле Windows 11 на базе `CustomTkinter`.

---

## 📥 Скачать готовый `.exe`

Вы можете скачать готовый исполняемый файл для Windows, не требующий установки Python:
👉 **[Скачать VirusTotal Scanner v1.0.0](../../releases)**

---

## 🛠️ Запуск из исходного кода

### Требования
* Python 3.10+
* Ключ API VirusTotal (бесплатно на [virustotal.com](https://www.virustotal.com/))

### Установка и запуск
1. Клонируйте репозиторий:
   ```bash
   git clone [https://github.com/ВАШ_ЛОГИН/VirusTotal-Folder-Scanner.git](https://github.com/ВАШ_ЛОГИН/VirusTotal-Folder-Scanner.git)
   cd VirusTotal-Folder-Scanner
