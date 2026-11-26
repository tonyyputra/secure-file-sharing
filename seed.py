"""
seed.py - Mengisi basis data dengan akun demo beserta berkas private key-nya.

Jalankan:
    python seed.py              # buat akun yang belum ada
    python seed.py --reset      # hapus akun demo beserta datanya, lalu buat ulang

Di dalam container:
    docker compose exec app python seed.py
    docker compose cp app:/app/data/seed_keys ./seed_keys

Catatan: alamat surel di bawah memakai domain example.com, yang direservasi
RFC 2606 untuk contoh dan pengujian, sehingga tidak mungkin mengenai alamat
milik orang sungguhan.

Berkas private key ditulis ke <SFS_DATA_DIR>/seed_keys/. Berkas itu terenkripsi
dengan passphrase masing-masing akun, tetapi tetap jangan di-commit: pola
*.pem dan seed_keys/ sudah ada di .gitignore.
"""
import os
import sys

from werkzeug.security import generate_password_hash

import crypto_service as cs
from app import DATA_DIR, STORAGE_DIR, app, get_db, now

# username, email dummy, password akun, passphrase private key
ACCOUNTS = [
    ("Tony", "tony@example.com", "tony1234", "ynot1234"),
    ("Eric", "eric@example.com", "eric1234", "cire1234"),
    ("Abi",  "abi@example.com",  "abia1234", "aiba1234"),
]

KEY_DIR = os.path.join(DATA_DIR, "seed_keys")


def purge(db, username):
    """Hapus satu akun demo beserta paket, catatan file, dan jejak auditnya."""
    row = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if row is None:
        return False
    uid = row["id"]
    for f in db.execute("SELECT stored_filename FROM shared_files WHERE sender_id=? OR recipient_id=?",
                        (uid, uid)).fetchall():
        try:
            os.remove(os.path.join(STORAGE_DIR, os.path.basename(f["stored_filename"])))
        except OSError:
            pass
    db.execute("DELETE FROM shared_files WHERE sender_id=? OR recipient_id=?", (uid, uid))
    db.execute("DELETE FROM audit_log WHERE user_id=?", (uid,))
    db.execute("DELETE FROM user_keys WHERE user_id=?", (uid,))
    db.execute("DELETE FROM users WHERE id=?", (uid,))
    return True


def create(db, username, email, password, passphrase):
    """Buat akun + dua pasang RSA, lalu tulis private key ke berkas.

    Kunci dibuat langsung lewat crypto_service, bukan lewat issue_keys(), karena
    issue_keys() hanya menaruh salinan PEM di memori proses selama 15 menit.
    Di sini PEM perlu ditulis ke berkas agar akun demo bisa langsung dipakai.
    """
    cur = db.execute("INSERT INTO users(username, email, password_hash, created_at) VALUES(?,?,?,?)",
                     (username, email, generate_password_hash(password), now()))
    uid = cur.lastrowid

    enc_key, sig_key = cs.generate_rsa_key(), cs.generate_rsa_key()
    db.execute("""INSERT INTO user_keys(user_id, encryption_public_key, signing_public_key, created_at)
                  VALUES(?,?,?,?)""",
               (uid, cs.export_public_pem(enc_key).decode(), cs.export_public_pem(sig_key).decode(), now()))

    written = []
    for kind, key in (("encryption", enc_key), ("signing", sig_key)):
        path = os.path.join(KEY_DIR, "%s_%s_private.pem" % (username.lower(), kind))
        with open(path, "wb") as f:
            f.write(cs.export_private_pem(key, passphrase))
        os.chmod(path, 0o600)
        written.append(os.path.basename(path))

    db.execute("INSERT INTO audit_log(created_at, user_id, username, action, detail, ip) VALUES(?,?,?,?,?,?)",
               (now(), uid, username, "seed", "akun demo dibuat oleh seed.py", None))
    return uid, written


def main():
    reset = "--reset" in sys.argv[1:]
    os.makedirs(KEY_DIR, exist_ok=True)

    with app.app_context():
        db = get_db()
        if reset:
            for username, *_ in ACCOUNTS:
                if purge(db, username):
                    print("  dihapus : %s (beserta paket, catatan file, dan jejak audit)" % username)

        print("\n%-6s %-20s %-10s %-10s %s" % ("Akun", "Email (dummy)", "Password", "Passphrase", "Status"))
        print("-" * 86)
        created = 0
        for username, email, password, passphrase in ACCOUNTS:
            if db.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
                status = "sudah ada, dilewati"
            else:
                _uid, files = create(db, username, email, password, passphrase)
                status = "dibuat + " + ", ".join(files)
                created += 1
            print("%-6s %-20s %-10s %-10s %s" % (username, email, password, passphrase, status))
        db.commit()

    print("-" * 86)
    if created:
        print("\n%d akun dibuat. Private key ada di:\n  %s" % (created, KEY_DIR))
        print("\nLogin pakai Password, dan saat mengirim/mendekripsi file unggah berkas .pem")
        print("yang sesuai lalu isi Passphrase (bukan Password).")
    else:
        print("\nTidak ada akun baru. Jalankan 'python seed.py --reset' untuk membuat ulang dari nol.")
        print("Private key akun yang sudah ada tidak bisa dipulihkan; --reset membuat kunci baru.")


if __name__ == "__main__":
    main()
