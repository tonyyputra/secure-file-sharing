# Secure File Sharing (AES-256-GCM + RSA-OAEP + RSA-PSS)

Aplikasi web untuk mengirim file ke pengguna terdaftar secara aman. Dibuat dengan **Python + Flask + SQLite + library `cryptography`**, sesuai laporan dan PPT Kelompok 2.

---

## 1. Cara menjalankan (dari nol)

### A. Pastikan Python terpasang
Buka Terminal (di VS Code: menu **Terminal → New Terminal**), lalu ketik:
```
python --version
```
Harus muncul Python 3.9 atau lebih baru. (Di Mac/Linux kadang perintahnya `python3`.)

### B. Buka folder proyek di VS Code
**File → Open Folder…** lalu pilih folder `secure_file_sharing` hasil ekstrak zip.

### C. Buat "virtual environment" (kotak terpisah untuk library proyek)
Windows:
```
python -m venv venv
venv\Scripts\activate
```
Mac/Linux:
```
python3 -m venv venv
source venv/bin/activate
```
Kalau berhasil, di depan baris terminal muncul tulisan `(venv)`.

> Windows PowerShell kadang menolak `activate`. Jalankan sekali: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, lalu ulangi.

### D. Pasang library
```
pip install -r requirements.txt
```

### E. Jalankan aplikasi
```
python app.py
```
Buka browser ke **http://127.0.0.1:5000**. Hentikan server dengan `Ctrl + C` di terminal.

---

## 2. Coba alurnya (butuh 2 akun)

Pakai **dua jendela browser**: satu biasa, satu **Incognito/Private**, supaya login-nya tidak bertabrakan.

1. **Jendela 1**: Daftar sebagai `Tony`. Di halaman Keys, **unduh kedua private key** (decryption + signing). Ingat passphrase yang kamu isi.
2. **Jendela 2 (incognito)**: Daftar sebagai `Eric`, unduh juga kedua key-nya.
3. Di jendela `Tony`: **Share File** → pilih penerima `Eric`, pilih file, unggah `tony_signing_private.pem`, isi passphrase → **Enkripsi dan kirim**.
4. Di jendela `Eric`: **Received Files** → **Verifikasi dan dekripsi** → unggah `eric_encryption_private.pem` + passphrase → file asli terunduh.

Coba juga skenario gagal: pakai key milik orang lain, passphrase salah, atau buka `/decrypt/1` dari akun ketiga. Aplikasi harus menolaknya.

> Penting: private key hanya tersedia untuk diunduh **15 menit setelah daftar** (disimpan sementara di memori server, bukan di database). Kalau terlewat atau server di-restart, buka halaman **Keys → Buat ulang pasangan kunci**.

---

## 3. Pengujian (Bab 6 laporan)

```
python test_app.py     # 14 tes otomatis: normal, gagal, akses ditolak, paket diubah, dll
python benchmark.py    # waktu enkripsi/sign/verify/dekripsi per ukuran file -> benchmark_results.csv
```
Hasil `benchmark.py` bisa langsung kamu pakai untuk bagian evaluasi performa di laporan akhir.

---

## 4. Isi folder

| File | Fungsi |
|---|---|
| `app.py` | Backend Flask: route, login/session, hak akses, upload/download, SQLite |
| `crypto_service.py` | Semua kriptografi: AES-GCM, RSA-OAEP, RSA-PSS, SHA-256, format paket `.sfs` |
| `templates/` | Halaman HTML: login, register, dashboard, share, sent, received, decrypt, keys |
| `static/style.css` | Tampilan |
| `test_app.py`, `benchmark.py` | Pengujian fungsi dan performa |
| `data/` | Dibuat otomatis: `sfs.db` (SQLite), `packages/` (paket `.sfs`), `secret_key` |

Tabel SQLite: `users`, `user_keys`, `shared_files` (sama dengan Bab 5.3).

## 5. Kesesuaian dengan laporan

- Registrasi/login, password di-hash (Werkzeug). Dua pasang RSA-2048 per user (enkripsi dan tanda tangan terpisah).
- Private key = PEM terenkripsi passphrase (`BestAvailableEncryption`), **tidak disimpan di SQLite**.
- Kirim: AES key + nonce acak per file → AES-256-GCM → AES key dikunci RSA-OAEP(SHA-256) dengan public key penerima → manifest (berisi hash SHA-256 ciphertext) ditandatangani RSA-PSS → paket `.sfs` (ZIP: `manifest.json`, `ciphertext.bin`, `signature.bin`) disimpan dengan nama acak.
- Terima: cek hak akses → hash ciphertext → verifikasi RSA-PSS → pulihkan AES key → dekripsi + cek authentication tag. Gagal di satu tahap = berhenti dan tahap yang gagal ditampilkan.
- Validasi: batas 10 MB, whitelist tipe file, cek key cocok dengan akun, proteksi CSRF, secret key kuat dibuat otomatis.
- File hasil dekripsi hanya ada di memori lalu langsung diunduh, tidak ada file sementara di disk.
- Satu pengiriman = satu penerima (batasan 6.2).

## 6. Batasan (sama seperti Bab 7.4 laporan)

- Server memproses file asli dan private key yang diunggah, jadi **ini bukan end-to-end encryption**.
- Kalau diakses lewat jaringan, wajib HTTPS/TLS. `python app.py` memakai server pengembangan Flask, jangan dipakai sebagai server produksi.
- Salinan sementara private key (15 menit setelah daftar) ada di memori proses server. Cocok untuk prototipe lokal, bukan produksi.

## 7. Masalah umum

| Gejala | Solusi |
|---|---|
| `python` tidak dikenali | Pasang Python dari python.org dan centang **Add Python to PATH**, lalu buka ulang terminal |
| `No module named flask` | Venv belum aktif atau `pip install -r requirements.txt` belum dijalankan |
| `Address already in use` | Port 5000 terpakai. Tutup server lama, atau ubah `port=5000` di baris terakhir `app.py` |
| "Private key tidak bisa dibuka" | Passphrase salah, atau yang diunggah bukan file `.pem` dari aplikasi ini |
| Tombol unduh key 404 | Salinan 15 menit sudah habis. Gunakan Keys → Buat ulang pasangan kunci |
