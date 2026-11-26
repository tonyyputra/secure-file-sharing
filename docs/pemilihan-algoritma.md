# Pemilihan Algoritma dan Model Ancaman

Bahan untuk bab landasan teori dan pembahasan. Setiap pilihan di bawah punya
alternatif yang layak; yang dinilai bukan hanya pilihannya, tapi alasannya.

---

## 1. Enkripsi isi file: AES-256-GCM

| Alternatif | Pertimbangan | Putusan |
|---|---|---|
| **AES-256-GCM** | AEAD: kerahasiaan dan integritas dalam satu operasi. Authentication tag 16 byte langsung mendeteksi perubahan ciphertext. Dipercepat perangkat keras (AES-NI). | **Dipakai** |
| AES-256-CBC + HMAC-SHA256 | Perlu dua kunci dan dua tahap, serta harus encrypt-then-MAC dengan urutan benar. Salah urutan membuka padding oracle. Lebih banyak kode, lebih banyak peluang salah. | Ditolak |
| AES-256-CBC saja | Tidak ada integritas sama sekali. Rentan padding oracle dan pembalikan bit. | Ditolak |
| ChaCha20-Poly1305 | Setara secara keamanan dan lebih cepat tanpa AES-NI. | Layak, tidak dipilih karena AES-NI tersedia dan AES lebih dikenal di literatur rujukan |

Syarat pemakaian GCM yang dipenuhi implementasi ini: **nonce 96 bit acak
dan AES key acak dibuat ulang untuk setiap file**. Pengulangan pasangan
(key, nonce) pada GCM bersifat katastrofik, bukan sekadar melemahkan:
keystream terpakai dua kali dan kunci autentikasi dapat dipulihkan.
Diuji oleh `test_nonce_unique`.

## 2. Pembungkusan kunci: RSA-2048-OAEP-SHA256

| Alternatif | Pertimbangan | Putusan |
|---|---|---|
| **RSA-OAEP-SHA256** | Padding dengan bukti keamanan, acak, tidak rentan serangan Bleichenbacher. | **Dipakai** |
| RSA PKCS#1 v1.5 | Masih umum tapi rentan serangan oracle padding (Bleichenbacher 1998 dan turunannya). | Ditolak |
| RSA "textbook" tanpa padding | Deterministik dan maleabel. Tidak aman. | Ditolak |
| ECIES / X25519 + HKDF | Kunci jauh lebih kecil (32 byte vs 256 byte), operasi lebih cepat, keamanan setara 3072-bit RSA. | Layak dan secara teknis lebih baik; tidak dipilih agar skema tetap satu keluarga algoritma (RSA untuk enkripsi dan tanda tangan) sehingga lebih mudah dijelaskan. Lihat bagian 5. |

Panjang 2048 bit mengikuti rekomendasi NIST SP 800-57 untuk pemakaian
sampai sekitar 2030 (setara kekuatan 112 bit).

## 3. Tanda tangan: RSA-2048-PSS-SHA256

| Alternatif | Pertimbangan | Putusan |
|---|---|---|
| **RSA-PSS** | Probabilistik dengan salt, punya bukti keamanan, standar modern untuk tanda tangan RSA. Salt 32 byte = panjang digest SHA-256. | **Dipakai** |
| RSA PKCS#1 v1.5 | Deterministik, masih diterima tapi tidak lagi dianjurkan untuk sistem baru. | Ditolak |
| Ed25519 | Lebih cepat, tanda tangan 64 byte, tanpa parameter yang bisa salah dikonfigurasi. | Layak, tidak dipilih dengan alasan sama seperti bagian 2 |

**Yang ditandatangani adalah manifest, bukan file.** Manifest memuat
`ciphertext_sha256`, jadi integritas ciphertext tercakup secara tidak
langsung (pola *hash-then-sign*). Keuntungannya: RSA-PSS bekerja atas data
berukuran tetap berapa pun besar filenya. Terlihat pada hasil benchmark,
waktu `sign` praktis konstan dari 1 KB sampai 10 MB.

## 4. Pemisahan kunci enkripsi dan kunci tanda tangan

Setiap pengguna memiliki **dua** pasang RSA, bukan satu yang dipakai untuk
dua keperluan. Alasannya:

1. Memakai satu kunci RSA untuk mengenkripsi sekaligus menandatangani dapat
   memungkinkan interaksi antar kedua operasi; ini prinsip *key separation*.
2. Peran kedua kunci berbeda dan masa pakainya bisa berbeda. Kunci tanda
   tangan yang bocor merusak autentikasi ke depan; kunci enkripsi yang bocor
   membuka seluruh arsip lampau.
3. Pesan kesalahan menjadi jelas: aplikasi dapat memastikan pengguna
   mengunggah berkas `.pem` yang tepat (`key_matches()`).

## 5. Model ancaman: apa yang dilindungi dan apa yang tidak

### Dilindungi

| Ancaman | Mekanisme | Diuji oleh |
|---|---|---|
| Penyadap membaca paket di penyimpanan | AES-256-GCM | `test_ciphertext_is_not_plaintext` |
| Ciphertext diubah | SHA-256 di manifest + authentication tag GCM | `test_tampered_ciphertext`, `test_tampered_stored_package` |
| Manifest diubah | RSA-PSS | `test_tampered_manifest` |
| Manifest diubah lalu ditandatangani ulang | AAD AES-GCM | `test_aad_binds_manifest_to_ciphertext` |
| Pengguna lain membuka file bukan miliknya | hak akses + RSA-OAEP | `test_flow_and_access_control` |
| Paket ditujukan ke orang lain | pemeriksaan identitas manifest vs basis data | `test_identity_mismatch` |
| Berkas `.pem` orang lain dipakai | `key_matches()` | `test_validation` |
| Penebakan password | scrypt (Werkzeug) + pembatas 5 percobaan per 5 menit | `test_login_rate_limited` |
| Enumerasi akun lewat timing | verifikasi hash selalu dijalankan | - |
| CSRF | token per sesi, `compare_digest` | `test_csrf_and_login_required` |
| ZIP bomb | batas ukuran tiap bagian paket | `test_oversized_part_rejected` |

### Tidak dilindungi (batasan yang disadari)

1. **Server tepercaya.** Server menerima file asli, private key yang
   diunggah, dan passphrase-nya. Siapa pun yang menguasai server dapat
   membaca semuanya. Sistem ini **bukan end-to-end encryption**. E2EE sejati
   menuntut operasi kriptografi dijalankan di browser (Web Crypto API)
   sehingga private key tidak pernah meninggalkan perangkat pengguna.
2. **Basis data sebagai otoritas kunci tunggal.** Public key diambil dari
   tabel `user_keys`. Penyerang yang bisa menulis ke tabel itu dapat menukar
   kunci dan menjadi perantara, sementara semua verifikasi tetap tampil
   berhasil. Mitigasi yang ada hanya parsial: sidik jari kunci ditampilkan di
   `/share` dan `/decrypt` agar pengguna dapat mencocokkannya lewat jalur
   terpisah. Solusi sebenarnya membutuhkan PKI atau jaringan kepercayaan.
3. **Tanpa kerahasiaan ke depan (forward secrecy).** AES key dibungkus
   langsung ke public key RSA penerima. Bila private key penerima bocor,
   seluruh paket lampau yang masih tersimpan dapat dibuka. Protokol dengan
   forward secrecy memakai kunci efemeral per sesi (misalnya X25519 ECDH).
4. **Tanpa pencabutan kunci.** Membuat ulang pasangan kunci membuat paket
   lama tidak dapat dibuka selamanya; tidak ada riwayat kunci dan tidak ada
   daftar pencabutan.
5. **Satu penerima per pengiriman.** Mengirim ke banyak penerima menuntut
   AES key dibungkus beberapa kali, satu per public key penerima.
6. **Passphrase private key tidak dapat dipulihkan.** Tidak ada mekanisme
   pemulihan, dan itu memang konsekuensi yang benar.
7. **Pembatas login hanya di memori proses.** Hilang saat server
   dijalankan ulang, dan tidak berlaku lintas proses bila aplikasi
   dijalankan dengan banyak worker.
8. **Wajib HTTPS/TLS di jaringan.** Tanpa TLS, password, passphrase, dan
   berkas `.pem` melintas sebagai teks terbuka. `python app.py` memakai
   server pengembangan Flask dan bukan untuk produksi.

---

## 6. Arah pengembangan

Urut dari yang paling berdampak:

1. **Pindahkan kriptografi ke browser** (Web Crypto API). Satu perubahan ini
   menghapus batasan nomor 1, yang merupakan kelemahan terbesar sistem.
2. **Ganti RSA dengan X25519 + HKDF + AES-GCM** dan Ed25519 untuk tanda
   tangan: kunci lebih kecil, lebih cepat, lebih sulit salah konfigurasi.
3. **Kunci efemeral per pengiriman** untuk mendapatkan forward secrecy.
4. **Verifikasi sidik jari yang dipaksakan** saat pertama kali berinteraksi
   dengan seorang penerima (pola trust-on-first-use seperti SSH).
5. **Dukungan banyak penerima** dengan membungkus AES key berkali-kali.
