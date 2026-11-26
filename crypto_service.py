"""
crypto_service.py
Semua logika kriptografi ada di file ini:
  - AES-256-GCM   : mengenkripsi isi file
  - RSA-OAEP      : mengamankan AES key dengan public key penerima
  - RSA-PSS       : menandatangani manifest
  - SHA-256       : hash ciphertext
Manifest juga dipakai sebagai associated data (AAD) AES-GCM, sehingga
identitas pengirim/penerima terikat ke ciphertext secara kriptografis.
Paket .sfs = ZIP berisi: manifest.json, ciphertext.bin, signature.bin
"""
import base64
import hashlib
import io
import json
import os
import time
import zipfile
import zlib

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAX_PACKAGE_PART = 12 * 1024 * 1024  # batas ukuran tiap bagian paket (anti ZIP bomb)
PACKAGE_PARTS = {"manifest.json", "ciphertext.bin", "signature.bin"}
PACKAGE_VERSION = 2

# Field manifest yang nilainya bergantung pada ciphertext atau AES key, jadi
# belum diketahui saat enkripsi dimulai dan tidak bisa dipakai sebagai AAD.
_AAD_EXCLUDED = ("encrypted_aes_key", "ciphertext_sha256")


class CryptoError(Exception):
    """Error kriptografi. `step` = tahap yang gagal, `message` = penjelasan untuk user."""

    def __init__(self, step, message):
        super().__init__(message)
        self.step = step
        self.message = message


def _oaep():
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def _pss():
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)


def _canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _aad(manifest):
    """Associated data untuk AES-256-GCM: manifest tanpa field turunan ciphertext.

    Mengikat ciphertext ke identitas pengirim/penerima, nama file asli, nonce,
    dan versi paket secara kriptografis. Tanpa ini, pengikatan tersebut hanya
    dijamin oleh tanda tangan RSA-PSS; dengan ini, mengubah salah satu field
    membuat authentication tag GCM langsung gagal walau tanda tangan valid.
    """
    return _canon({k: v for k, v in manifest.items() if k not in _AAD_EXCLUDED})


def _b64(b):
    return base64.b64encode(b).decode("ascii")


def _unb64(s):
    return base64.b64decode(s.encode("ascii"), validate=True)


# ---------------------------------------------------------------- manajemen kunci
def generate_rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def export_private_pem(key, passphrase):
    """Private key -> PEM terenkripsi passphrase (BestAvailableEncryption)."""
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(passphrase.encode("utf-8")),
    )


def export_public_pem(private_key):
    return private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def load_private_key(pem_bytes, passphrase, step="Membuka private key"):
    try:
        key = serialization.load_pem_private_key(pem_bytes, password=passphrase.encode("utf-8"))
    except (ValueError, TypeError, UnicodeDecodeError):
        raise CryptoError(step, "Private key tidak bisa dibuka. Periksa file PEM dan passphrase-nya.")
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size != 2048:
        raise CryptoError(step, "File yang diunggah bukan private key RSA-2048 dari aplikasi ini.")
    return key


def key_matches(private_key, public_pem):
    """Cek apakah private key ini pasangan dari public key yang tersimpan di database."""
    if isinstance(public_pem, str):
        public_pem = public_pem.encode("utf-8")
    return export_public_pem(private_key).strip() == public_pem.strip()


def fingerprint(public_pem):
    if isinstance(public_pem, str):
        public_pem = public_pem.encode("utf-8")
    h = hashlib.sha256(public_pem.strip()).hexdigest()[:32]
    return ":".join(h[i:i + 4] for i in range(0, 32, 4))


# ---------------------------------------------------------------- membuat paket
def build_package(plaintext, filename, sender, recipient, recipient_enc_public_pem, signing_private_key):
    """Enkripsi + tanda tangan. Return (bytes paket .sfs, dict waktu dalam ms)."""
    timings = {}
    try:
        recipient_pub = serialization.load_pem_public_key(
            recipient_enc_public_pem.encode("utf-8") if isinstance(recipient_enc_public_pem, str)
            else recipient_enc_public_pem
        )
    except ValueError:
        raise CryptoError("Mengambil public key penerima", "Public key penerima tidak valid.")

    # 1) Header manifest disusun lebih dulu supaya bisa dipakai sebagai AAD
    header = {
        "version": PACKAGE_VERSION,
        "sender": sender,
        "recipient": recipient,
        "original_filename": filename,
        "sent_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "nonce": _b64(os.urandom(12)),
        "algorithms": {"file": "AES-256-GCM", "key": "RSA-2048-OAEP-SHA256", "signature": "RSA-2048-PSS-SHA256"},
    }

    # 2) AES-256-GCM: key acak 256 bit + nonce acak 96 bit (baru untuk setiap file).
    #    Header diikutkan sebagai associated data (lihat _aad).
    t = time.perf_counter()
    aes_key = AESGCM.generate_key(bit_length=256)
    ciphertext = AESGCM(aes_key).encrypt(_unb64(header["nonce"]), plaintext, _aad(header))
    timings["encrypt_aes"] = (time.perf_counter() - t) * 1000  # tag 16 byte menempel di akhir

    # 3) RSA-OAEP: amankan AES key dengan public key penerima
    t = time.perf_counter()
    encrypted_key = recipient_pub.encrypt(aes_key, _oaep())
    timings["wrap_key"] = (time.perf_counter() - t) * 1000

    # 4) Manifest lengkap = header + AES key terenkripsi + hash SHA-256 ciphertext
    manifest = dict(header, encrypted_aes_key=_b64(encrypted_key),
                    ciphertext_sha256=hashlib.sha256(ciphertext).hexdigest())
    manifest_bytes = _canon(manifest)

    # 5) RSA-PSS: tanda tangani manifest
    t = time.perf_counter()
    signature = signing_private_key.sign(manifest_bytes, _pss(), hashes.SHA256())
    timings["sign"] = (time.perf_counter() - t) * 1000

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        z.writestr("manifest.json", manifest_bytes)
        z.writestr("ciphertext.bin", ciphertext)
        z.writestr("signature.bin", signature)
    return buf.getvalue(), timings


# ---------------------------------------------------------------- membuka paket
def read_package(package_bytes):
    try:
        z = zipfile.ZipFile(io.BytesIO(package_bytes))
    except zipfile.BadZipFile:
        raise CryptoError("Membaca paket .sfs", "Format paket tidak valid atau rusak.")
    if {i.filename for i in z.infolist()} != PACKAGE_PARTS:
        raise CryptoError("Membaca paket .sfs", "Isi paket tidak lengkap atau tidak sesuai format.")
    if any(i.file_size > MAX_PACKAGE_PART for i in z.infolist()):
        raise CryptoError("Membaca paket .sfs", "Ukuran isi paket tidak wajar.")
    try:
        return z.read("manifest.json"), z.read("ciphertext.bin"), z.read("signature.bin")
    except (zipfile.BadZipFile, zlib.error, EOFError, NotImplementedError):
        raise CryptoError("Membaca paket .sfs", "Paket rusak atau telah diubah (pemeriksaan integritas arsip gagal).")


def open_package(package_bytes, sender_signing_public_pem, recipient_private_key,
                 expected_sender, expected_recipient):
    """
    Urutan sesuai laporan 5.2.3:
      hash ciphertext -> verifikasi RSA-PSS -> pulihkan AES key (RSA-OAEP)
      -> dekripsi AES-GCM dengan manifest sebagai associated data.
    Return (plaintext, manifest, dict waktu ms). Raise CryptoError kalau salah satu tahap gagal.
    """
    timings = {}
    manifest_bytes, ciphertext, signature = read_package(package_bytes)

    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
        if not isinstance(manifest, dict):
            raise ValueError("manifest bukan objek JSON")
        expected_hash = manifest["ciphertext_sha256"]
        nonce = _unb64(manifest["nonce"])
        encrypted_key = _unb64(manifest["encrypted_aes_key"])
        aad = _aad(manifest)
    except (ValueError, KeyError, TypeError):
        raise CryptoError("Membaca manifest", "Manifest rusak atau formatnya tidak valid.")

    if manifest.get("version") != PACKAGE_VERSION:
        raise CryptoError("Membaca manifest",
                          "Versi paket %r tidak didukung aplikasi ini (versi yang didukung: %d)."
                          % (manifest.get("version"), PACKAGE_VERSION))

    # 1) Hash ciphertext vs manifest
    t = time.perf_counter()
    if hashlib.sha256(ciphertext).hexdigest() != expected_hash:
        raise CryptoError("Pemeriksaan hash ciphertext", "Hash ciphertext tidak cocok dengan manifest. Paket telah berubah.")
    timings["hash"] = (time.perf_counter() - t) * 1000

    # 2) Verifikasi tanda tangan RSA-PSS
    t = time.perf_counter()
    try:
        pub = serialization.load_pem_public_key(
            sender_signing_public_pem.encode("utf-8") if isinstance(sender_signing_public_pem, str)
            else sender_signing_public_pem
        )
        pub.verify(signature, manifest_bytes, _pss(), hashes.SHA256())
    except (InvalidSignature, ValueError):
        raise CryptoError("Verifikasi tanda tangan RSA-PSS",
                          "Tanda tangan tidak valid. Manifest berubah atau bukan dari pengirim yang tercatat.")
    timings["verify"] = (time.perf_counter() - t) * 1000

    # 3) Identitas di manifest harus sama dengan catatan database
    if manifest.get("sender") != expected_sender or manifest.get("recipient") != expected_recipient:
        raise CryptoError("Pemeriksaan identitas", "Pengirim/penerima di manifest tidak sesuai catatan sistem.")

    # 4) RSA-OAEP: pulihkan AES key
    t = time.perf_counter()
    try:
        aes_key = recipient_private_key.decrypt(encrypted_key, _oaep())
    except ValueError:
        raise CryptoError("Memulihkan AES key (RSA-OAEP)", "AES key tidak bisa dipulihkan. Private key bukan milik penerima paket ini.")
    timings["unwrap_key"] = (time.perf_counter() - t) * 1000

    # 5) AES-256-GCM: dekripsi + cek authentication tag
    t = time.perf_counter()
    try:
        plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext, aad)
    except (InvalidTag, ValueError):
        raise CryptoError("Dekripsi AES-256-GCM", "Authentication tag tidak valid. Data terenkripsi telah berubah.")
    timings["decrypt_aes"] = (time.perf_counter() - t) * 1000
    return plaintext, manifest, timings
