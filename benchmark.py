"""
benchmark.py - Evaluasi performa untuk bagian pengujian laporan.

Jalankan:  python benchmark.py
Hasil ditulis ke benchmark_results.csv dan benchmark_keygen.csv

Yang diukur:
  1. Pembuatan pasangan kunci RSA-2048. Ini operasi termahal di sistem dan
     variansinya besar (bergantung pencarian bilangan prima), jadi dilaporkan
     terpisah lengkap dengan min/maks.
  2. Tiap tahap kriptografi per ukuran file, dilaporkan sebagai
     rata-rata +/- deviasi standar. Rata-rata tanpa deviasi tidak bisa
     disimpulkan apa-apa, terutama pada file kecil yang didominasi biaya RSA.
  3. Baseline AES-256-GCM murni, untuk memisahkan biaya enkripsi simetris
     dari overhead kriptografi asimetris (RSA-OAEP + RSA-PSS + SHA-256).
     Angka "enkripsi 12 ms" tidak bermakna tanpa pembanding ini.
"""
import csv
import os
import statistics
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import crypto_service as cs

SIZES = [("1 KB", 1024), ("100 KB", 100 * 1024), ("1 MB", 1024 ** 2),
         ("5 MB", 5 * 1024 ** 2), ("10 MB", 10 * 1024 ** 2)]
REPEAT = 5
KEYGEN_REPEAT = 10


def ms(fn):
    t = time.perf_counter()
    r = fn()
    return (time.perf_counter() - t) * 1000, r


def fmt(samples):
    """rata-rata +/- deviasi standar, dalam ms."""
    if len(samples) < 2:
        return "%.2f" % samples[0]
    return "%.2f +/- %.2f" % (statistics.fmean(samples), statistics.stdev(samples))


# ---------------------------------------------------------------- 1. keygen RSA
print("1. Pembuatan pasangan kunci RSA-2048 (%d kali)" % KEYGEN_REPEAT)
keygen = [ms(cs.generate_rsa_key)[0] for _ in range(KEYGEN_REPEAT)]
print("   rata-rata   : %.2f ms" % statistics.fmean(keygen))
print("   deviasi std : %.2f ms" % statistics.stdev(keygen))
print("   min / maks  : %.2f / %.2f ms" % (min(keygen), max(keygen)))
print("   Catatan: satu registrasi membuat DUA pasang kunci, jadi biaya"
      "\n   registrasi kira-kira dua kali angka di atas.\n")

with open("benchmark_keygen.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["pengukuran_ke", "keygen_ms"])
    w.writerows(enumerate(("%.3f" % v for v in keygen), start=1))

# ---------------------------------------------------------------- 2. per ukuran
sig_key, enc_key = cs.generate_rsa_key(), cs.generate_rsa_key()
sig_pub, enc_pub = cs.export_public_pem(sig_key), cs.export_public_pem(enc_key)

# SHA-256 dipisahkan dari verifikasi RSA-PSS karena biayanya tumbuh dengan
# ukuran file, sedangkan biaya operasi asimetris tidak.
STAGES = ("aes_enc", "wrap", "sign", "hash", "verify", "unwrap", "aes_dec", "baseline")
HEAD = ("Ukuran", "AES enkripsi", "RSA-OAEP wrap", "RSA-PSS sign", "SHA-256",
        "RSA-PSS verify", "RSA-OAEP unwrap", "AES dekripsi", "AES murni (baseline)")
print("2. Tiap tahap per ukuran file, ms (rata-rata +/- deviasi standar, %d kali)" % REPEAT)
print("   " + " | ".join(HEAD))

rows = []
for label, size in SIZES:
    data = os.urandom(size)
    acc = {k: [] for k in STAGES}

    for _ in range(REPEAT):
        pkg, tb = cs.build_package(data, "f.bin", "alice", "bob", enc_pub, sig_key)
        _plain, _man, to = cs.open_package(pkg, sig_pub, enc_key, "alice", "bob")
        acc["aes_enc"].append(tb["encrypt_aes"])
        acc["wrap"].append(tb["wrap_key"])
        acc["sign"].append(tb["sign"])
        acc["hash"].append(to["hash"])
        acc["verify"].append(to["verify"])
        acc["unwrap"].append(to["unwrap_key"])
        acc["aes_dec"].append(to["decrypt_aes"])

        # Baseline: AES-256-GCM saja, tanpa RSA, tanpa tanda tangan, tanpa ZIP.
        key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)
        t, ct = ms(lambda: AESGCM(key).encrypt(nonce, data, None))
        acc["baseline"].append(t)

    cols = [fmt(acc[k]) for k in STAGES]
    rows.append([label] + cols)
    print("   " + label + " | " + " | ".join(cols))

    asym = sum(statistics.fmean(acc[k]) for k in ("wrap", "sign", "verify", "unwrap"))
    sym = statistics.fmean(acc["baseline"])
    hsh = statistics.fmean(acc["hash"])
    print("     -> asimetris (tetap) %.2f ms | SHA-256 %.2f ms | AES murni %.2f ms"
          % (asym, hsh, sym))

with open("benchmark_results.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["ukuran", "aes_enkripsi_ms", "rsa_oaep_wrap_ms", "rsa_pss_sign_ms", "sha256_ms",
                "rsa_pss_verify_ms", "rsa_oaep_unwrap_ms", "aes_dekripsi_ms", "aes_murni_baseline_ms"])
    w.writerows(rows)

print("\nTersimpan di benchmark_results.csv dan benchmark_keygen.csv")
print("Catatan: biaya RSA tidak bergantung ukuran file, jadi pada file kecil ia"
      "\nmendominasi total, sementara pada file besar AES yang mendominasi.")
