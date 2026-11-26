# Secure File Sharing (AES-256-GCM + RSA-OAEP + RSA-PSS)

Aplikasi web untuk mengirim file ke pengguna terdaftar secara aman. Dibuat dengan **Python + Flask + SQLite + library `cryptography`**, sesuai laporan dan PPT Kelompok 2.

---

## 1. Cara menjalankan (dari nol)

### A. Pastikan Python terpasang
Buka Terminal (di VS Code: menu **Terminal → New Terminal**), lalu ketik:
```
python --version
```
Harus muncul **Python 3.11 atau lebih baru** (diuji pada 3.11 sampai 3.14). Di Mac/Linux kadang perintahnya `python3`.

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
4. Di jendela `Eric`: **Received Files** (ada penanda jumlah file baru di menu) → **Verifikasi dan dekripsi** → unggah `eric_encryption_private.pem` + passphrase → file asli terunduh.
5. Buka menu **Audit** di kedua akun: semua aktivitas tercatat, termasuk percobaan yang gagal.

Coba juga skenario gagal: pakai key milik orang lain, passphrase salah, atau buka `/decrypt/1` dari akun ketiga. Aplikasi harus menolaknya.

**Verifikasi sidik jari.** Halaman Share menampilkan sidik jari kunci enkripsi tiap penerima, dan halaman Verify & Decrypt menampilkan sidik jari signing key pengirim. Cocokkan lewat jalur lain (tatap muka, telepon) sebelum mengirim file penting — lihat `docs/pemilihan-algoritma.md` bagian 5 soal mengapa ini perlu.

> Penting: private key hanya tersedia untuk diunduh **15 menit setelah daftar** (disimpan sementara di memori server, bukan di database). Kalau terlewat atau server di-restart, buka halaman **Keys → Buat ulang pasangan kunci**.

---

## 3. Pengujian (Bab 6 laporan)

```
python test_app.py     # 25 tes otomatis: normal, gagal, akses ditolak, paket diubah, audit, dll
python benchmark.py    # performa per tahap -> benchmark_results.csv + benchmark_keygen.csv
```

`benchmark.py` melaporkan:
- waktu pembuatan pasangan kunci RSA-2048 (operasi termahal; deviasi standarnya besar, jadi min/maks ikut dilaporkan),
- tiap tahap kriptografi per ukuran file sebagai **rata-rata ± deviasi standar**,
- **baseline AES-256-GCM murni** sebagai pembanding, supaya terlihat berapa sebenarnya overhead kriptografi asimetris.

Pola yang muncul dan layak dibahas di laporan: biaya RSA praktis **tetap** di semua ukuran file (sekitar 1,5–2 ms), sementara SHA-256 dan AES tumbuh linier dan mendominasi pada file besar.

---

## 4. Isi folder

| File | Fungsi |
|---|---|
| `app.py` | Backend Flask: route, login/session, hak akses, upload/download, audit, SQLite |
| `crypto_service.py` | Semua kriptografi: AES-GCM, RSA-OAEP, RSA-PSS, SHA-256, format paket `.sfs` |
| `templates/` | Halaman HTML: login, register, dashboard, share, sent, received, decrypt, keys |
| `static/style.css` | Tampilan |
| `test_app.py`, `benchmark.py` | Pengujian fungsi dan performa |
| `docs/arsitektur.md` | Diagram arsitektur, sequence enkripsi/dekripsi, ERD, format paket `.sfs` |
| `docs/pemilihan-algoritma.md` | Justifikasi tiap algoritma beserta alternatifnya, dan model ancaman |
| `data/` | Dibuat otomatis: `sfs.db` (SQLite), `packages/` (paket `.sfs`), `secret_key` |

Tabel SQLite: `users`, `user_keys`, `shared_files`, `audit_log`. Diagram relasinya ada di `docs/arsitektur.md`.

> **Penting saat mengumpulkan tugas.** Jangan ikutkan `venv/`, `__pycache__/`, dan `data/`. Folder `data/` memuat `secret_key`, yaitu `SECRET_KEY` Flask — siapa pun yang memegangnya bisa memalsukan session cookie. Ketiganya sudah masuk `.gitignore`.

## 5. Kesesuaian dengan laporan

- Registrasi/login, password di-hash (Werkzeug). Dua pasang RSA-2048 per user (enkripsi dan tanda tangan terpisah).
- Private key = PEM terenkripsi passphrase (`BestAvailableEncryption`), **tidak disimpan di SQLite**.
- Kirim: AES key + nonce acak per file → AES-256-GCM (**manifest dipakai sebagai associated data**) → AES key dikunci RSA-OAEP(SHA-256) dengan public key penerima → manifest (berisi hash SHA-256 ciphertext) ditandatangani RSA-PSS → paket `.sfs` (ZIP: `manifest.json`, `ciphertext.bin`, `signature.bin`) disimpan dengan nama acak.
- Terima: cek hak akses → hash ciphertext → verifikasi RSA-PSS → cek identitas manifest → pulihkan AES key → dekripsi + cek authentication tag (AAD). Gagal di satu tahap = berhenti dan tahap yang gagal ditampilkan.
- Validasi: batas 10 MB, whitelist tipe file, cek key cocok dengan akun, proteksi CSRF, pembatas percobaan login, secret key kuat dibuat otomatis.
- Jejak audit: semua aktivitas (termasuk kegagalan dan tahap kegagalannya) tercatat di `audit_log` dan bisa dilihat pengguna di menu **Audit**.
- File hasil dekripsi hanya ada di memori lalu langsung diunduh, tidak ada file sementara di disk.
- Satu pengiriman = satu penerima (batasan 6.2).
- Pengirim bisa menarik kembali kiriman dan penerima bisa menghapus paket yang sudah diunduh.

## 6. Batasan (sama seperti Bab 7.4 laporan)

Daftar lengkap beserta alasan teknis dan arah perbaikannya ada di `docs/pemilihan-algoritma.md` bagian 5 dan 6. Ringkasnya:

- Server memproses file asli dan private key yang diunggah, jadi **ini bukan end-to-end encryption**.
- Public key diambil dari basis data server, jadi **server adalah otoritas kunci tunggal**. Penyerang yang bisa menulis ke tabel `user_keys` dapat menjadi perantara tanpa terdeteksi. Sidik jari kunci ditampilkan agar pengguna bisa mencocokkannya lewat jalur lain, tapi itu mitigasi parsial, bukan PKI.
- **Tidak ada forward secrecy.** AES key dibungkus langsung ke public key penerima, jadi private key yang bocor membuka seluruh paket lampau.
- **Tidak ada pencabutan kunci.** Membuat ulang kunci membuat paket lama tidak bisa dibuka selamanya.
- Pembatas percobaan login hanya di memori proses: hilang saat server dijalankan ulang dan tidak berlaku lintas worker.
- Kolom `email` dikumpulkan tapi belum dipakai; notifikasi ke penerima masih berupa penanda di dalam aplikasi, bukan surel.
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
| "Terlalu banyak percobaan login" | Pembatas 5 percobaan per 5 menit aktif. Tunggu, atau jalankan ulang server saat sedang mengembangkan |
| "Versi paket tidak didukung" | Paket dibuat versi aplikasi lama (format v1, tanpa AAD). Kirim ulang filenya |
