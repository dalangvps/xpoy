# Xpoy v2.0 - The Professional Penetrator 👑

https://ibb.co/N65t9dkF

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/Python-3.x-yellow.svg)]()
[![Status](https://img.shields.io/badge/Status-Active-green.svg)]()

> Developed for CYBER INDO (CI) by Zero.

## 💀 Deskripsi Singkat
**Xpoy v2.0** adalah *Web Penetration Testing* dan *Vulnerability Scanner* berbasis Python yang dirancang untuk pengujian keamanan profesional (*White Hat*). *Tools* ini **secara agresif dan rekursif** menjelajahi seluruh *website* target, mengidentifikasi semua parameter yang dapat diuji, dan secara otomatis **menembakkan multi-payload** untuk menemukan kerentanan kritis seperti **SQL Injection (SQLi)**, **Cross-Site Scripting (XSS)**, dan **Local File Inclusion (LFI)**.

Xpoy beroperasi dengan efisiensi tinggi, berfokus hanya pada *logic* aplikasi dengan mengabaikan *file* statis, menjadikannya alat yang ideal untuk *Bug Bounty* dan *Initial Pentesting*.

## 🔥 Fitur Brutal (Key Features)

* **Deep Recursive Crawling:** Menjelajahi *seluruh link* di dalam satu domain (**same-scope**) secara mendalam, melewati *file* statis (`.jpg`, `.css`, dll.). (Status: Sikat ✅)
* **Multi-Payload Injection:** Menggunakan *payload bank* yang diperluas untuk menguji **SQLi (Error-Based)**, **XSS (Reflected)**, dan **LFI (Basic)**. (Status: Sikat ✅)
* **Comprehensive Parameter Extraction:** Mengambil semua parameter dari URL *Query*, *Form Input* (`<input>`, `<textarea>`), dan *Anchor Links*. (Status: Sikat ✅)
* **Proof-of-Concept URL:** Menyajikan **URL Bukti (PoC)** yang dapat langsung diverifikasi untuk setiap kerentanan yang ditemukan. (Status: Sikat ✅)
* **Stealth Mode:** Menggunakan *User-Agent* yang menyerupai *browser* dan *session* persisten untuk menghindari *block* sederhana. (Status: Sikat ✅)
* **Efficiency Filter:** Mengabaikan parameter umum yang tidak relevan (`PHPSESSID`, `utm_source`) untuk hasil *scanning* yang lebih bersih. (Status: Sikat ✅)

## 🛠️ Persiapan dan Instalasi

Xpoy dibangun dengan Python 3 dan hanya membutuhkan *library* `requests`.

### Instalasi di Termux (Android) 📱

1.  **Update Sistem & Install Dependensi:**
    ```bash
    pkg update && pkg upgrade -y
    pkg install python git -y
    ```

2.  **Clone Repository & Install Library:**
    ```bash
    git clone https://github.com/dalangvps/xpoy
    cd xpoy
    pip install requests
    ```

### Instalasi di Kali Linux / Debian 💻

1.  **Update Sistem & Install Dependensi:**
    ```bash
    sudo apt update && sudo apt upgrade -y
    sudo apt install python3 python3-pip git -y
    ```

2.  **Clone Repository & Install Library:**
    ```bash
    git clone https://github.com/dalangvps/xpoy
    cd xpoy
    pip3 install requests
    ```

## 🚀 Cara Eksekusi (The Command)

Setelah instalasi, jalankan Xpoy dengan *flag* `-u` diikuti dengan URL target Anda.

```bash
# Untuk Kali Linux
python3 run.py -u <URL_TARGET>

# Untuk Termux
python run.py -u <URL_TARGET>
