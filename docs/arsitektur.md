# Arsitektur dan Alur Sistem

Dokumen ini memuat diagram untuk bagian perancangan laporan. Blok `mermaid`
dirender otomatis di GitHub/GitLab; bila perlu gambar untuk dokumen cetak,
tempel kodenya ke <https://mermaid.live> dan ekspor PNG/SVG.

---

## 1. Arsitektur sistem

```mermaid
flowchart TB
    subgraph Klien
        B1["Browser pengirim"]
        B2["Browser penerima"]
    end
    subgraph Server["Server Flask (127.0.0.1:5000)"]
        R["app.py<br/>route, sesi, hak akses, CSRF"]
        C["crypto_service.py<br/>AES-GCM, RSA-OAEP, RSA-PSS, SHA-256"]
        R <--> C
    end
    subgraph Penyimpanan["data/"]
        DB[("sfs.db<br/>users, user_keys,<br/>shared_files, audit_log")]
        PKG["packages/*.sfs"]
        SK["secret_key"]
    end
    MEM["PENDING_KEYS<br/>(memori, TTL 15 menit)"]

    B1 -- "file asli + signing private key + passphrase" --> R
    B2 -- "decryption private key + passphrase" --> R
    R -- "file hasil dekripsi (hanya di memori)" --> B2
    R --> DB
    R --> PKG
    R --> SK
    R --> MEM

    classDef risk fill:#fff4e8,stroke:#d85a1f
    class MEM,R risk
```

Kotak berwarna menandai titik di mana server memegang data sensitif dalam
bentuk terbuka. Inilah sebabnya sistem ini **bukan end-to-end encryption**
(lihat `pemilihan-algoritma.md` bagian 4 dan README bagian Batasan).

---

## 2. Alur pengiriman (enkripsi dan penandatanganan)

```mermaid
sequenceDiagram
    autonumber
    actor P as Pengirim
    participant F as app.py
    participant C as crypto_service
    participant DB as SQLite
    participant S as data/packages

    P->>F: POST /share (file, signing key .pem, passphrase, penerima)
    F->>F: validasi tipe file, ukuran <= 10 MB, CSRF
    F->>DB: ambil encryption_public_key penerima
    F->>C: load_private_key(pem, passphrase)
    F->>C: key_matches() - signing key benar milik pengirim?
    C->>C: susun header manifest (versi, identitas, nama file, nonce)
    C->>C: AES-256-GCM: enkripsi file, AAD = header manifest
    C->>C: RSA-OAEP: kunci AES key dengan public key penerima
    C->>C: SHA-256 ciphertext, lengkapi manifest
    C->>C: RSA-PSS: tanda tangani manifest
    C-->>F: paket .sfs (ZIP: manifest.json, ciphertext.bin, signature.bin)
    F->>S: simpan dengan nama acak (uuid4)
    F->>DB: catat shared_files + audit_log(share_ok)
    F-->>P: konfirmasi + waktu tiap tahap
```

## 3. Alur penerimaan (verifikasi dan dekripsi)

Urutan ini berhenti pada kegagalan pertama, dan tahap yang gagal
ditampilkan ke pengguna.

```mermaid
sequenceDiagram
    autonumber
    actor R as Penerima
    participant F as app.py
    participant C as crypto_service
    participant DB as SQLite

    R->>F: POST /decrypt/<id> (decryption key .pem, passphrase)
    F->>DB: ambil baris shared_files
    F->>F: hak akses - recipient_id == pengguna login?
    Note over F: gagal di sini -> HTTP 403
    F->>DB: ambil signing_public_key pengirim
    F->>C: load_private_key + key_matches()
    C->>C: 1. baca paket .sfs, cek kelengkapan dan ukuran bagian
    C->>C: 2. SHA-256 ciphertext == manifest.ciphertext_sha256?
    C->>C: 3. RSA-PSS verify(manifest, signature, public key pengirim)
    C->>C: 4. manifest.sender/recipient == catatan basis data?
    C->>C: 5. RSA-OAEP: pulihkan AES key
    C->>C: 6. AES-256-GCM decrypt, AAD = manifest, cek authentication tag
    C-->>F: plaintext (hanya di memori)
    F->>DB: status='downloaded' + audit_log(decrypt_ok)
    F-->>R: unduhan file asli
    Note over F,C: gagal di tahap 1-6 -> HTTP 422 + audit_log(decrypt_fail)
```

---

## 4. Struktur basis data

```mermaid
erDiagram
    users ||--o| user_keys : "memiliki satu pasang"
    users ||--o{ shared_files : "mengirim"
    users ||--o{ shared_files : "menerima"
    users ||--o{ audit_log : "mencatat"

    users {
        INTEGER id PK
        TEXT username UK
        TEXT email UK
        TEXT password_hash
        TEXT created_at
    }
    user_keys {
        INTEGER id PK
        INTEGER user_id FK_UK
        TEXT encryption_public_key
        TEXT signing_public_key
        TEXT created_at
    }
    shared_files {
        INTEGER id PK
        INTEGER sender_id FK
        INTEGER recipient_id FK
        TEXT original_filename
        TEXT stored_filename
        INTEGER file_size
        TEXT package_path
        TEXT created_at
        TEXT status
    }
    audit_log {
        INTEGER id PK
        TEXT created_at
        INTEGER user_id
        TEXT username
        TEXT action
        INTEGER file_id
        TEXT detail
        TEXT ip
    }
```

Private key **tidak pernah** masuk ke tabel mana pun. Satu-satunya salinan di
server ada di `PENDING_KEYS` (memori proses) selama 15 menit setelah kunci
dibuat, agar pengguna sempat mengunduhnya.

---

## 5. Format paket `.sfs`

```
paket.sfs  (arsip ZIP, ZIP_STORED / tanpa kompresi)
|
+-- manifest.json     JSON kanonik (kunci terurut, tanpa spasi)
|     version              = 2
|     sender, recipient    identitas, dicocokkan dengan basis data
|     original_filename
|     sent_at
|     nonce                96 bit, base64, acak per file
|     algorithms           keterangan algoritma yang dipakai
|     encrypted_aes_key    AES key 256 bit dibungkus RSA-OAEP-SHA256
|     ciphertext_sha256    hash heksadesimal ciphertext
|
+-- ciphertext.bin    AES-256-GCM(plaintext), authentication tag 16 byte
|                     menempel di akhir. AAD = manifest tanpa field
|                     encrypted_aes_key dan ciphertext_sha256.
|
+-- signature.bin     RSA-PSS-SHA256 atas byte manifest.json
```

Dua lapis integritas yang saling melengkapi:

| Lapis | Melindungi | Gagal bila |
|---|---|---|
| `ciphertext_sha256` + RSA-PSS | seluruh paket, termasuk asal pengirim | ciphertext atau manifest diubah tanpa signing key pengirim |
| AAD AES-256-GCM | ikatan ciphertext ke isi manifest | manifest diubah lalu ditandatangani ulang oleh pemegang signing key |

Tanpa lapis AAD, pemegang signing key pengirim dapat memasangkan ciphertext
dengan manifest lain (mengubah nama file atau identitas penerima) dan paket
tetap lolos semua pemeriksaan.
