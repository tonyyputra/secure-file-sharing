"""
app.py - Aplikasi Secure File Sharing (Flask + SQLite)
Jalankan:  python app.py   lalu buka http://127.0.0.1:5000
"""
import io
import os
import re
import secrets
import sqlite3
import time
import uuid
from datetime import datetime
from functools import wraps
from urllib.parse import urlparse

from flask import (Flask, Response, abort, flash, g, redirect, render_template,
                   request, send_file, session, url_for)
from markupsafe import Markup
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

import crypto_service as cs

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("SFS_DATA_DIR", os.path.join(BASE_DIR, "data"))
STORAGE_DIR = os.path.join(DATA_DIR, "packages")
DB_PATH = os.path.join(DATA_DIR, "sfs.db")
os.makedirs(STORAGE_DIR, exist_ok=True)

MAX_FILE_MB = 10
MAX_KEY_BYTES = 20 * 1024
ALLOWED_EXT = {"pdf", "txt", "md", "csv", "png", "jpg", "jpeg", "gif", "docx", "xlsx",
               "pptx", "zip", "json", "py"}
PENDING_TTL = 15 * 60
PENDING_KEYS = {}  # user_id -> {"enc": bytes, "sig": bytes, "expires": float}  (hanya di memori)

# Pembatasan percobaan login (anti brute force). Disimpan di memori proses.
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW = 5 * 60       # jendela pengamatan, detik
LOGIN_LOCKOUT = 5 * 60      # lama penguncian setelah batas terlampaui, detik
LOGIN_ATTEMPTS = {}         # kunci -> {"count": int, "first": float, "until": float}

# Hash tiruan: dipakai agar username yang tidak ada tetap memakan waktu
# verifikasi yang sama dengan username yang ada (anti enumerasi lewat timing).
DUMMY_PASSWORD_HASH = generate_password_hash("sfs-dummy-password-for-constant-time")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS user_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE REFERENCES users(id),
    encryption_public_key TEXT NOT NULL,
    signing_public_key TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS shared_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL REFERENCES users(id),
    recipient_id INTEGER NOT NULL REFERENCES users(id),
    original_filename TEXT NOT NULL,
    stored_filename TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    package_path TEXT NOT NULL,
    created_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'sent'
);
"""

app = Flask(__name__)


def _load_secret_key():
    path = os.path.join(DATA_DIR, "secret_key")
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(secrets.token_hex(32))
    with open(path) as f:
        return f.read().strip()


app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or _load_secret_key(),
    MAX_CONTENT_LENGTH=(MAX_FILE_MB + 1) * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)


# ------------------------------------------------------------------ database
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


with sqlite3.connect(DB_PATH) as _c:
    _c.executescript(SCHEMA)


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ------------------------------------------------------------------ keamanan dasar
@app.before_request
def load_user_and_check_csrf():
    g.user = None
    if session.get("user_id"):
        g.user = get_db().execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
        if g.user is None:
            session.clear()
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    if request.method == "POST":
        sent = request.form.get("csrf_token", "")
        if not secrets.compare_digest(sent, session["csrf"]):
            abort(400, "Token keamanan form tidak valid. Muat ulang halaman lalu coba lagi.")


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.context_processor
def inject_helpers():
    return {"csrf_input": lambda: Markup('<input type="hidden" name="csrf_token" value="%s">' % session.get("csrf", ""))}


@app.template_filter("filesize")
def filesize(n):
    for unit in ("B", "KB", "MB"):
        if n < 1024 or unit == "MB":
            return ("%d %s" % (n, unit)) if unit == "B" else ("%.1f %s" % (n, unit))
        n /= 1024.0


def login_required(view):
    @wraps(view)
    def wrapped(*a, **kw):
        if g.user is None:
            flash("Silakan login dulu.", "error")
            return redirect(url_for("login"))
        return view(*a, **kw)
    return wrapped


def safe_redirect_back(fallback="dashboard"):
    """Redirect ke halaman sebelumnya, tapi hanya jika Referer menunjuk ke host ini.
    Tanpa pemeriksaan ini, header Referer (dikendalikan penyerang) bisa dipakai
    untuk open redirect ke situs luar."""
    ref = request.referrer
    if ref:
        u = urlparse(ref)
        if not u.netloc or u.netloc == request.host:
            return redirect(ref)
    return redirect(url_for(fallback))


def login_rate_limit(username):
    """Return sisa detik penguncian, atau 0 kalau masih boleh mencoba."""
    key = "%s|%s" % (request.remote_addr or "-", username.lower())
    rec = LOGIN_ATTEMPTS.get(key)
    t = time.time()
    if rec and rec["until"] > t:
        return int(rec["until"] - t) + 1
    if rec and t - rec["first"] > LOGIN_WINDOW:
        rec = None
    LOGIN_ATTEMPTS[key] = rec or {"count": 0, "first": t, "until": 0.0}
    return 0


def login_record_failure(username):
    key = "%s|%s" % (request.remote_addr or "-", username.lower())
    rec = LOGIN_ATTEMPTS.setdefault(key, {"count": 0, "first": time.time(), "until": 0.0})
    rec["count"] += 1
    if rec["count"] >= LOGIN_MAX_ATTEMPTS:
        rec["until"] = time.time() + LOGIN_LOCKOUT
        rec["count"] = 0
        rec["first"] = time.time()


def login_record_success(username):
    LOGIN_ATTEMPTS.pop("%s|%s" % (request.remote_addr or "-", username.lower()), None)


@app.errorhandler(413)
def too_large(_e):
    flash("File terlalu besar. Batas maksimal %d MB." % MAX_FILE_MB, "error")
    return safe_redirect_back("share")


@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(400)
def http_error(e):
    return render_template("error.html", code=e.code, message=e.description), e.code


# ------------------------------------------------------------------ kunci
def issue_keys(user_id, passphrase, replace=False):
    """Buat 2 pasang RSA. Public key -> SQLite. Private key (PEM ber-passphrase) -> memori sementara."""
    enc_key, sig_key = cs.generate_rsa_key(), cs.generate_rsa_key()
    db = get_db()
    enc_pub = cs.export_public_pem(enc_key).decode()
    sig_pub = cs.export_public_pem(sig_key).decode()
    if replace:
        db.execute("UPDATE user_keys SET encryption_public_key=?, signing_public_key=?, created_at=? WHERE user_id=?",
                   (enc_pub, sig_pub, now(), user_id))
    else:
        db.execute("INSERT INTO user_keys(user_id, encryption_public_key, signing_public_key, created_at) VALUES(?,?,?,?)",
                   (user_id, enc_pub, sig_pub, now()))
    PENDING_KEYS[user_id] = {
        "enc": cs.export_private_pem(enc_key, passphrase),
        "sig": cs.export_private_pem(sig_key, passphrase),
        "expires": time.time() + PENDING_TTL,
    }


def pending_for(user_id):
    p = PENDING_KEYS.get(user_id)
    if p and p["expires"] < time.time():
        PENDING_KEYS.pop(user_id, None)
        return None
    return p


# ------------------------------------------------------------------ akun
@app.route("/")
def index():
    return redirect(url_for("dashboard" if g.user else "login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        passphrase = request.form.get("passphrase", "")
        errors = []
        if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):
            errors.append("Username 3-30 karakter: huruf, angka, atau underscore.")
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            errors.append("Format email tidak valid.")
        if len(password) < 8:
            errors.append("Password minimal 8 karakter.")
        if password != confirm:
            errors.append("Konfirmasi password tidak sama.")
        if len(passphrase) < 8:
            errors.append("Passphrase private key minimal 8 karakter.")
        if passphrase == password and passphrase:
            errors.append("Passphrase private key sebaiknya berbeda dari password akun.")
        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("register.html", username=username, email=email)
        db = get_db()
        try:
            cur = db.execute("INSERT INTO users(username, email, password_hash, created_at) VALUES(?,?,?,?)",
                             (username, email, generate_password_hash(password), now()))
        except sqlite3.IntegrityError:
            flash("Username atau email sudah dipakai.", "error")
            return render_template("register.html", username=username, email=email)
        issue_keys(cur.lastrowid, passphrase)
        db.commit()
        session.clear()
        session["user_id"] = cur.lastrowid
        flash("Akun dibuat. Unduh kedua private key sekarang, lalu simpan baik-baik.", "success")
        return redirect(url_for("keys"))
    return render_template("register.html", username="", email="")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        locked = login_rate_limit(username)
        if locked:
            flash("Terlalu banyak percobaan login. Coba lagi dalam %d detik." % locked, "error")
            return render_template("login.html"), 429
        user = get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        # Selalu jalankan verifikasi hash, termasuk saat username tidak ada,
        # supaya waktu respons tidak membocorkan ada/tidaknya akun.
        stored_hash = user["password_hash"] if user else DUMMY_PASSWORD_HASH
        ok = check_password_hash(stored_hash, password)
        if user and ok:
            login_record_success(username)
            session.clear()
            session["user_id"] = user["id"]
            return redirect(url_for("dashboard"))
        login_record_failure(username)
        flash("Username atau password salah.", "error")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


# ------------------------------------------------------------------ halaman utama
FILE_QUERY = """
SELECT s.*, su.username AS sender_name, ru.username AS recipient_name
FROM shared_files s JOIN users su ON su.id = s.sender_id JOIN users ru ON ru.id = s.recipient_id
"""


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    uid = g.user["id"]
    sent = db.execute(FILE_QUERY + " WHERE s.sender_id=? ORDER BY s.id DESC", (uid,)).fetchall()
    received = db.execute(FILE_QUERY + " WHERE s.recipient_id=? ORDER BY s.id DESC", (uid,)).fetchall()
    return render_template("dashboard.html", sent=sent, received=received)


@app.route("/sent")
@login_required
def sent_files():
    rows = get_db().execute(FILE_QUERY + " WHERE s.sender_id=? ORDER BY s.id DESC", (g.user["id"],)).fetchall()
    return render_template("sent.html", rows=rows)


@app.route("/received")
@login_required
def received_files():
    rows = get_db().execute(FILE_QUERY + " WHERE s.recipient_id=? ORDER BY s.id DESC", (g.user["id"],)).fetchall()
    return render_template("received.html", rows=rows)


# ------------------------------------------------------------------ share file
def _recipients():
    return get_db().execute("SELECT username FROM users WHERE id != ? ORDER BY username", (g.user["id"],)).fetchall()


@app.route("/share", methods=["GET", "POST"])
@login_required
def share():
    if request.method == "GET":
        return render_template("share.html", recipients=_recipients(), selected="", timings=None)

    db = get_db()
    recipient_name = request.form.get("recipient", "")
    upload = request.files.get("file")
    key_file = request.files.get("signing_key")
    passphrase = request.form.get("passphrase", "")

    def fail(msg):
        flash(msg, "error")
        return render_template("share.html", recipients=_recipients(), selected=recipient_name, timings=None)

    rec = db.execute("""SELECT u.id, u.username, k.encryption_public_key FROM users u
                        JOIN user_keys k ON k.user_id = u.id WHERE u.username = ?""", (recipient_name,)).fetchone()
    if rec is None or rec["id"] == g.user["id"]:
        return fail("Pilih penerima yang terdaftar (bukan akun Anda sendiri).")
    if not upload or not upload.filename:
        return fail("Pilih file yang akan dikirim.")
    filename = secure_filename(upload.filename) or "file"
    if filename.rsplit(".", 1)[-1].lower() not in ALLOWED_EXT or "." not in filename:
        return fail("Tipe file tidak diizinkan. Tipe yang boleh: " + ", ".join(sorted(ALLOWED_EXT)) + ".")
    data = upload.read()
    if len(data) == 0:
        return fail("File kosong tidak bisa dikirim.")
    if len(data) > MAX_FILE_MB * 1024 * 1024:
        return fail("File terlalu besar. Batas maksimal %d MB." % MAX_FILE_MB)
    if not key_file or not key_file.filename or not passphrase:
        return fail("Unggah signing private key (.pem) dan isi passphrase-nya.")
    key_pem = key_file.read(MAX_KEY_BYTES + 1)
    if len(key_pem) > MAX_KEY_BYTES:
        return fail("File private key terlalu besar.")

    try:
        sig_priv = cs.load_private_key(key_pem, passphrase, "Membuka signing private key")
        own = db.execute("SELECT signing_public_key FROM user_keys WHERE user_id=?", (g.user["id"],)).fetchone()
        if not cs.key_matches(sig_priv, own["signing_public_key"]):
            raise cs.CryptoError("Memeriksa signing key", "Private key ini bukan signing key milik akun Anda. "
                                 "Pastikan Anda mengunggah file *_signing_private.pem.")
        package, timings = cs.build_package(data, filename, g.user["username"], rec["username"],
                                            rec["encryption_public_key"], sig_priv)
    except cs.CryptoError as e:
        return fail("%s: %s" % (e.step, e.message))

    stored = uuid.uuid4().hex + ".sfs"  # nama acak di server
    with open(os.path.join(STORAGE_DIR, stored), "wb") as f:
        f.write(package)
    db.execute("""INSERT INTO shared_files(sender_id, recipient_id, original_filename, stored_filename,
                  file_size, package_path, created_at, status) VALUES(?,?,?,?,?,?,?,'sent')""",
               (g.user["id"], rec["id"], filename, stored, len(data), os.path.join("packages", stored), now()))
    db.commit()
    flash("File %s terenkripsi, ditandatangani, dan dikirim ke %s." % (filename, rec["username"]), "success")
    return render_template("share.html", recipients=_recipients(), selected="", timings=timings)


# ------------------------------------------------------------------ verify & decrypt
@app.route("/decrypt/<int:file_id>", methods=["GET", "POST"])
@login_required
def decrypt(file_id):
    db = get_db()
    row = db.execute(FILE_QUERY + " WHERE s.id = ?", (file_id,)).fetchone()
    if row is None:
        abort(404, "File tidak ditemukan.")
    if row["recipient_id"] != g.user["id"]:
        abort(403, "Anda tidak memiliki hak akses ke file ini.")
    if request.method == "GET":
        return render_template("decrypt.html", row=row, error=None, step=None)

    def fail(step, msg):
        return render_template("decrypt.html", row=row, error=msg, step=step), 422

    key_file = request.files.get("decryption_key")
    passphrase = request.form.get("passphrase", "")
    if not key_file or not key_file.filename or not passphrase:
        return fail("Input", "Unggah decryption private key (.pem) dan isi passphrase-nya.")
    key_pem = key_file.read(MAX_KEY_BYTES + 1)
    if len(key_pem) > MAX_KEY_BYTES:
        return fail("Input", "File private key terlalu besar.")

    pkg_path = os.path.join(STORAGE_DIR, os.path.basename(row["stored_filename"]))
    if not os.path.isfile(pkg_path):
        return fail("Membaca paket .sfs", "File paket tidak ditemukan di server.")
    with open(pkg_path, "rb") as f:
        package = f.read()

    sender_keys = db.execute("SELECT signing_public_key FROM user_keys WHERE user_id=?", (row["sender_id"],)).fetchone()
    my_keys = db.execute("SELECT encryption_public_key FROM user_keys WHERE user_id=?", (g.user["id"],)).fetchone()
    try:
        enc_priv = cs.load_private_key(key_pem, passphrase, "Membuka decryption private key")
        if not cs.key_matches(enc_priv, my_keys["encryption_public_key"]):
            raise cs.CryptoError("Memeriksa decryption key", "Private key ini bukan decryption key milik akun Anda. "
                                 "Pastikan Anda mengunggah file *_encryption_private.pem.")
        plaintext, _manifest, _t = cs.open_package(package, sender_keys["signing_public_key"], enc_priv,
                                                   row["sender_name"], row["recipient_name"])
    except cs.CryptoError as e:
        return fail(e.step, e.message)

    db.execute("UPDATE shared_files SET status='downloaded' WHERE id=?", (file_id,))
    db.commit()
    return send_file(io.BytesIO(plaintext), as_attachment=True, download_name=row["original_filename"],
                     mimetype="application/octet-stream")


# ------------------------------------------------------------------ kelola kunci
@app.route("/keys")
@login_required
def keys():
    k = get_db().execute("SELECT * FROM user_keys WHERE user_id=?", (g.user["id"],)).fetchone()
    return render_template("keys.html", pending=pending_for(g.user["id"]), k=k,
                           enc_fp=cs.fingerprint(k["encryption_public_key"]),
                           sig_fp=cs.fingerprint(k["signing_public_key"]))


@app.route("/keys/download/<kind>")
@login_required
def key_download(kind):
    p = pending_for(g.user["id"])
    if kind not in ("enc", "sig") or p is None:
        abort(404, "Private key tidak tersedia untuk diunduh. Buat ulang pasangan kunci di halaman Keys.")
    name = "%s_%s_private.pem" % (g.user["username"], "encryption" if kind == "enc" else "signing")
    return Response(p[kind], mimetype="application/x-pem-file",
                    headers={"Content-Disposition": 'attachment; filename="%s"' % name})


@app.route("/keys/clear", methods=["POST"])
@login_required
def key_clear():
    PENDING_KEYS.pop(g.user["id"], None)
    flash("Salinan sementara private key di server sudah dihapus.", "success")
    return redirect(url_for("keys"))


@app.route("/keys/regenerate", methods=["POST"])
@login_required
def key_regenerate():
    passphrase = request.form.get("passphrase", "")
    if not check_password_hash(g.user["password_hash"], request.form.get("password", "")):
        flash("Password akun salah.", "error")
    elif len(passphrase) < 8:
        flash("Passphrase minimal 8 karakter.", "error")
    else:
        issue_keys(g.user["id"], passphrase, replace=True)
        get_db().commit()
        flash("Pasangan kunci baru dibuat. File lama yang ditujukan ke Anda tidak bisa dibuka lagi dengan kunci baru.", "success")
    return redirect(url_for("keys"))


if __name__ == "__main__":
    # Server pengembangan Flask: hanya untuk belajar/testing lokal, bukan produksi.
    app.run(host="127.0.0.1", port=5000, debug=False)
