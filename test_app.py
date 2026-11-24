"""
test_app.py - Tes otomatis sesuai tabel test case.
Jalankan:  python test_app.py
"""
import io
import os
import tempfile
import unittest
import zipfile
import json
import hashlib

os.environ["SFS_DATA_DIR"] = tempfile.mkdtemp(prefix="sfs_test_")

import crypto_service as cs  # noqa: E402
from app import app, PENDING_KEYS  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding  # noqa: E402

PASS = "passphrase-kuat-123"


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

    def test_nonce_unique(self):
        p2, _ = cs.build_package(self.data, "a.txt", "alice", "bob", self.rcpt_enc_pub, self.sender_sig)
        n1 = json.loads(cs.read_package(self.pkg)[0])["nonce"]
        n2 = json.loads(cs.read_package(p2)[0])["nonce"]
        self.assertNotEqual(n1, n2)


class WebTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        cls.clients = {}
        cls.keys = {}
        for name in ("alice", "bob", "mallory"):
            c = app.test_client()
            r = c.post("/register", data=_form(c, username=name, email=name + "@x.com", password="password123",
                                                confirm="password123", passphrase=PASS), follow_redirects=True)
            assert r.status_code == 200, r.data
            cls.clients[name] = c
            cls.keys[name] = {k: c.get("/keys/download/" + k).data for k in ("enc", "sig")}

    def post_share(self, c, **kw):
        return c.post("/share", data=_form(c, **kw), content_type="multipart/form-data")

    def share_to_bob(self, content=b"rahasia kuliah", name="catatan.txt"):
        c = self.clients["alice"]
        r = self.post_share(c, recipient="bob", file=(io.BytesIO(content), name),
                            signing_key=(io.BytesIO(self.keys["alice"]["sig"]), "k.pem"), passphrase=PASS)
        self.assertIn(b"terenkripsi", r.data)

    def decrypt(self, user, fid, key_user=None, kind="enc", passphrase=PASS):
        c = self.clients[user]
        key = self.keys[key_user or user][kind]
        return c.post("/decrypt/%d" % fid, data=_form(c, decryption_key=(io.BytesIO(key), "k.pem"), passphrase=passphrase),
                      content_type="multipart/form-data")

    def test_flow_and_access_control(self):  # TC 1,2,3,11
        self.share_to_bob()
        self.assertIn(b"catatan.txt", self.clients["bob"].get("/received").data)
        fid = 1
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
        self.share_to_bob(b"data penting", "b.txt")
        row_dir = os.path.join(os.environ["SFS_DATA_DIR"], "packages")
        newest = max((os.path.join(row_dir, f) for f in os.listdir(row_dir)), key=os.path.getmtime)
        raw = bytearray(open(newest, "rb").read())
        raw[100] ^= 0xFF
        open(newest, "wb").write(bytes(raw))
        from app import get_db
        with app.app_context():
            fid = get_db().execute("SELECT MAX(id) FROM shared_files").fetchone()[0]
        self.assertEqual(self.decrypt("bob", fid).status_code, 422)


def _form(client, **fields):
    with client.session_transaction() as s:
        s.setdefault("csrf", "t" * 32)
        token = s["csrf"]
    fields["csrf_token"] = token
    return fields


if __name__ == "__main__":
    unittest.main(verbosity=2)
