"""
test_app.py - Tes otomatis sesuai tabel test case.
Jalankan:  python test_app.py
"""
import io
import os
import tempfile
import time
import unittest
import warnings
import zipfile
import json
import hashlib

os.environ["SFS_DATA_DIR"] = tempfile.mkdtemp(prefix="sfs_test_")

import crypto_service as cs  # noqa: E402
from app import (LOGIN_MAX_ATTEMPTS, MAX_FILE_MB, PENDING_KEYS, app,  # noqa: E402
                 get_db)
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding  # noqa: E402

PASS = "passphrase-kuat-123"


def register(name):
    """Daftarkan satu akun baru dan ambil kedua private key-nya."""
    c = app.test_client()
    r = c.post("/register", data=_form(c, username=name, email=name + "@x.com", password="password123",
                                       confirm="password123", passphrase=PASS), follow_redirects=True)
    assert r.status_code == 200, r.data
    return c, {k: c.get("/keys/download/" + k).data for k in ("enc", "sig")}


def latest_file_id():
    with app.app_context():
        return get_db().execute("SELECT MAX(id) FROM shared_files").fetchone()[0]


def make_pair():
    k = cs.generate_rsa_key()
    return k, cs.export_public_pem(k).decode()


class CryptoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sender_sig, cls.sender_sig_pub = make_pair()
        cls.rcpt_enc, cls.rcpt_enc_pub = make_pair()
        cls.other_enc, _ = make_pair()
        cls.data = os.urandom(50_000)
        cls.pkg, _ = cs.build_package(cls.data, "a.txt", "alice", "bob", cls.rcpt_enc_pub, cls.sender_sig)

    def open(self, pkg, enc=None, sig_pub=None):
        return cs.open_package(pkg, sig_pub or self.sender_sig_pub, enc or self.rcpt_enc, "alice", "bob")

    def test_roundtrip(self):  # TC 3,4,5,6,7
        plain, manifest, _ = self.open(self.pkg)
        self.assertEqual(plain, self.data)
        self.assertEqual(manifest["original_filename"], "a.txt")

    def test_ciphertext_is_not_plaintext(self):  # TC 4
        _m, ct, _s = cs.read_package(self.pkg)
        self.assertNotIn(self.data[:64], ct)
        self.assertEqual(len(ct), len(self.data) + 16)  # + authentication tag

    def _repack(self, manifest=None, ciphertext=None, signature=None):
        m, ct, s = cs.read_package(self.pkg)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("manifest.json", manifest if manifest is not None else m)
            z.writestr("ciphertext.bin", ciphertext if ciphertext is not None else ct)
            z.writestr("signature.bin", signature if signature is not None else s)
        return buf.getvalue()

    def test_tampered_ciphertext(self):  # TC 8
        _m, ct, _s = cs.read_package(self.pkg)
        bad = bytes([ct[0] ^ 1]) + ct[1:]
        with self.assertRaises(cs.CryptoError) as c:
            self.open(self._repack(ciphertext=bad))
        self.assertIn("hash", c.exception.step.lower())

    def test_tampered_manifest(self):  # TC 8
        m, _c, _s = cs.read_package(self.pkg)
        with self.assertRaises(cs.CryptoError) as c:
            self.open(self._repack(manifest=m.replace(b"a.txt", b"x.txt")))
        self.assertIn("tanda tangan", c.exception.step.lower())

    def test_signature_from_other_key(self):  # TC 7
        _k, other_pub = make_pair()
        with self.assertRaises(cs.CryptoError):
            self.open(self.pkg, sig_pub=other_pub)

    def test_wrong_private_key(self):  # TC 9
        with self.assertRaises(cs.CryptoError) as c:
            self.open(self.pkg, enc=self.other_enc)
        self.assertIn("RSA-OAEP", c.exception.step)

    def test_invalid_auth_tag(self):  # TC 10: penyerang punya signing key, ubah ciphertext + hash + tanda tangan
        m, ct, _s = cs.read_package(self.pkg)
        bad = bytes([ct[0] ^ 1]) + ct[1:]
        man = json.loads(m)
        man["ciphertext_sha256"] = hashlib.sha256(bad).hexdigest()
        mb = json.dumps(man, sort_keys=True, separators=(",", ":")).encode()
        sig = self.sender_sig.sign(mb, cs._pss(), hashes.SHA256())
        with self.assertRaises(cs.CryptoError) as c:
            self.open(self._repack(manifest=mb, ciphertext=bad, signature=sig))
        self.assertIn("AES-256-GCM", c.exception.step)

    def test_wrong_passphrase(self):
        pem = cs.export_private_pem(self.rcpt_enc, PASS)
        with self.assertRaises(cs.CryptoError):
            cs.load_private_key(pem, "salah-passphrase")

    def test_garbage_package(self):
        with self.assertRaises(cs.CryptoError):
            self.open(b"bukan zip")

    def test_identity_mismatch(self):
        """Manifest valid dan bertanda tangan sah, tapi penerima tidak sesuai catatan basis data."""
        with self.assertRaises(cs.CryptoError) as c:
            cs.open_package(self.pkg, self.sender_sig_pub, self.rcpt_enc, "alice", "carol")
        self.assertIn("identitas", c.exception.step.lower())

    def test_aad_binds_manifest_to_ciphertext(self):
        """Penyerang yang memegang signing key pengirim mengubah field manifest lalu
        menandatanganinya ulang. Hash dan tanda tangan jadi konsisten, tapi AAD
        AES-GCM tidak lagi cocok sehingga dekripsi harus gagal."""
        m, ct, _s = cs.read_package(self.pkg)
        man = json.loads(m)
        man["original_filename"] = "palsu.txt"
        mb = cs._canon(man)
        sig = self.sender_sig.sign(mb, cs._pss(), hashes.SHA256())
        with self.assertRaises(cs.CryptoError) as c:
            self.open(self._repack(manifest=mb, ciphertext=ct, signature=sig))
        self.assertIn("AES-256-GCM", c.exception.step)

    def test_unsupported_version_rejected(self):
        m, ct, _s = cs.read_package(self.pkg)
        man = json.loads(m)
        man["version"] = cs.PACKAGE_VERSION + 1
        mb = cs._canon(man)
        sig = self.sender_sig.sign(mb, cs._pss(), hashes.SHA256())
        with self.assertRaises(cs.CryptoError) as c:
            self.open(self._repack(manifest=mb, ciphertext=ct, signature=sig))
        self.assertIn("Versi paket", c.exception.message)

    def test_oversized_part_rejected(self):
        """Pertahanan anti ZIP bomb: bagian paket yang ukuran aslinya melebihi
        MAX_PACKAGE_PART ditolak sebelum dibaca ke memori."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("manifest.json", b"{}")
            z.writestr("ciphertext.bin", b"\0" * (cs.MAX_PACKAGE_PART + 1))
            z.writestr("signature.bin", b"x")
        with self.assertRaises(cs.CryptoError) as c:
            cs.read_package(buf.getvalue())
        self.assertIn("tidak wajar", c.exception.message)

    def test_fingerprint_stable_and_distinct(self):
        _k, pub_a = make_pair()
        self.assertEqual(cs.fingerprint(pub_a), cs.fingerprint(pub_a))
        self.assertNotEqual(cs.fingerprint(pub_a), cs.fingerprint(self.sender_sig_pub))

    def test_nonce_unique(self):
        p2, _ = cs.build_package(self.data, "a.txt", "alice", "bob", self.rcpt_enc_pub, self.sender_sig)
        n1 = json.loads(cs.read_package(self.pkg)[0])["nonce"]
        n2 = json.loads(cs.read_package(p2)[0])["nonce"]
        self.assertNotEqual(n1, n2)


class WebTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        cls.clients, cls.keys = {}, {}
        for name in ("alice", "bob", "mallory"):
            cls.clients[name], cls.keys[name] = register(name)

    def post_share(self, c, **kw):
        return c.post("/share", data=_form(c, **kw), content_type="multipart/form-data")

    def share_to_bob(self, content=b"rahasia kuliah", name="catatan.txt"):
        c = self.clients["alice"]
        r = self.post_share(c, recipient="bob", file=(io.BytesIO(content), name),
                            signing_key=(io.BytesIO(self.keys["alice"]["sig"]), "k.pem"), passphrase=PASS)
        self.assertIn(b"terenkripsi", r.data)
        return latest_file_id()

    def decrypt(self, user, fid, key_user=None, kind="enc", passphrase=PASS):
        c = self.clients[user]
        key = self.keys[key_user or user][kind]
        return c.post("/decrypt/%d" % fid, data=_form(c, decryption_key=(io.BytesIO(key), "k.pem"), passphrase=passphrase),
                      content_type="multipart/form-data")

    def test_flow_and_access_control(self):  # TC 1,2,3,11
        fid = self.share_to_bob()
        self.assertIn(b"catatan.txt", self.clients["bob"].get("/received").data)
        ok = self.decrypt("bob", fid)
        self.assertEqual(ok.status_code, 200)
        self.assertEqual(ok.data, b"rahasia kuliah")
        self.assertEqual(self.decrypt("mallory", fid).status_code, 403)       # akun lain ditolak
        self.assertEqual(self.decrypt("alice", fid).status_code, 403)        # pengirim tidak bisa dekripsi
        self.assertEqual(self.decrypt("bob", fid, key_user="mallory").status_code, 422)  # key bukan milik bob
        self.assertEqual(self.decrypt("bob", fid, kind="sig").status_code, 422)          # salah jenis key
        self.assertEqual(self.decrypt("bob", fid, passphrase="salah-salah").status_code, 422)

    def test_validation(self):  # TC 12 + validasi
        c = self.clients["alice"]
        r = self.post_share(c, recipient="bob", file=(io.BytesIO(b"x"), "evil.exe"),
                            signing_key=(io.BytesIO(self.keys["alice"]["sig"]), "k.pem"), passphrase=PASS)
        self.assertIn("Tipe file tidak diizinkan".encode(), r.data)
        r = self.post_share(c, recipient="bob", file=(io.BytesIO(b"x"), "a.txt"),
                            signing_key=(io.BytesIO(self.keys["bob"]["sig"]), "k.pem"), passphrase=PASS)
        self.assertIn(b"bukan signing key", r.data)  # signing key milik orang lain
        r = self.post_share(c, recipient="alice", file=(io.BytesIO(b"x"), "a.txt"),
                            signing_key=(io.BytesIO(self.keys["alice"]["sig"]), "k.pem"), passphrase=PASS)
        self.assertIn(b"Pilih penerima", r.data)

    def test_csrf_and_login_required(self):
        c = app.test_client()
        self.assertEqual(c.get("/dashboard").status_code, 302)
        self.assertEqual(c.post("/login", data={"username": "a", "password": "b"}).status_code, 400)

    def test_tampered_stored_package(self):  # TC 8 lewat web
        fid = self.share_to_bob(b"data penting", "b.txt")
        row_dir = os.path.join(os.environ["SFS_DATA_DIR"], "packages")
        newest = max((os.path.join(row_dir, f) for f in os.listdir(row_dir)), key=os.path.getmtime)
        with open(newest, "rb") as f:
            raw = bytearray(f.read())
        raw[100] ^= 0xFF
        with open(newest, "wb") as f:
            f.write(bytes(raw))
        self.assertEqual(self.decrypt("bob", fid).status_code, 422)


class WebSecurityTests(unittest.TestCase):
    """Batas ukuran, masa berlaku kunci sementara, pembatas login, hak akses hapus, audit."""

    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        cls.clients, cls.keys = {}, {}
        for name in ("sender1", "receiver1", "outsider1"):
            cls.clients[name], cls.keys[name] = register(name)

    def send(self, content=b"isi rahasia", name="lampiran.txt"):
        c = self.clients["sender1"]
        r = c.post("/share", data=_form(c, recipient="receiver1", file=(io.BytesIO(content), name),
                   signing_key=(io.BytesIO(self.keys["sender1"]["sig"]), "k.pem"), passphrase=PASS),
                   content_type="multipart/form-data")
        self.assertIn(b"terenkripsi", r.data)
        return latest_file_id()

    def test_file_size_limit(self):
        """Batas 10 MB ditegakkan lewat MAX_CONTENT_LENGTH sebelum file masuk memori."""
        c = self.clients["sender1"]
        big = io.BytesIO(b"\0" * ((MAX_FILE_MB + 1) * 1024 * 1024 + 1024))
        with warnings.catch_warnings():
            # Werkzeug menumpahkan unggahan besar ke berkas sementara dan tidak
            # menutupnya di jalur permintaan yang ditolak; abaikan khusus di sini.
            warnings.simplefilter("ignore", ResourceWarning)
            r = c.post("/share", data=_form(c, recipient="receiver1", file=(big, "besar.txt"),
                       signing_key=(io.BytesIO(self.keys["sender1"]["sig"]), "k.pem"), passphrase=PASS),
                       content_type="multipart/form-data")
        self.assertIn(r.status_code, (302, 413))

    def test_pending_key_expires(self):
        """Salinan private key di memori server hanya berlaku selama PENDING_TTL."""
        c, _k = register("expiring1")
        self.assertEqual(c.get("/keys/download/enc").status_code, 200)
        with app.app_context():
            uid = get_db().execute("SELECT id FROM users WHERE username='expiring1'").fetchone()["id"]
        PENDING_KEYS[uid]["expires"] = time.time() - 1
        self.assertEqual(c.get("/keys/download/enc").status_code, 404)
        self.assertNotIn(uid, PENDING_KEYS)  # entri kedaluwarsa dibuang dari memori

    def test_login_rate_limited(self):
        c = app.test_client()
        codes = [c.post("/login", data=_form(c, username="sender1", password="salah")).status_code
                 for _ in range(LOGIN_MAX_ATTEMPTS + 2)]
        self.assertIn(429, codes)
        self.assertEqual(codes[0], 200)  # percobaan pertama belum dikunci

    def test_delete_requires_participation(self):
        fid = self.send()
        outsider = self.clients["outsider1"]
        self.assertEqual(outsider.post("/files/%d/delete" % fid, data=_form(outsider)).status_code, 403)
        rec = self.clients["receiver1"]
        self.assertIn(rec.post("/files/%d/delete" % fid, data=_form(rec)).status_code, (302, 303))
        self.assertEqual(rec.get("/decrypt/%d" % fid).status_code, 404)

    def test_audit_records_success_and_failure(self):
        fid = self.send(b"untuk audit", "audit.txt")
        rec = self.clients["receiver1"]
        rec.post("/decrypt/%d" % fid, data=_form(rec, decryption_key=(io.BytesIO(self.keys["outsider1"]["enc"]), "k.pem"),
                 passphrase=PASS), content_type="multipart/form-data")
        rec.post("/decrypt/%d" % fid, data=_form(rec, decryption_key=(io.BytesIO(self.keys["receiver1"]["enc"]), "k.pem"),
                 passphrase=PASS), content_type="multipart/form-data")
        trail = rec.get("/audit").data
        self.assertIn(b"decrypt_fail", trail)
        self.assertIn(b"decrypt_ok", trail)
        self.assertIn(b"share_ok", self.clients["sender1"].get("/audit").data)

    def test_audit_is_private_per_user(self):
        """Jejak audit satu pengguna tidak boleh memuat aktivitas pengguna lain."""
        self.send(b"rahasia", "privat.txt")
        self.assertNotIn(b"share_ok", self.clients["outsider1"].get("/audit").data)


def _form(client, **fields):
    with client.session_transaction() as s:
        s.setdefault("csrf", "t" * 32)
        token = s["csrf"]
    fields["csrf_token"] = token
    return fields


if __name__ == "__main__":
    unittest.main(verbosity=2)
