"""
benchmark.py - Mengukur waktu enkripsi, sign, verify, dekripsi untuk beberapa ukuran file (Bab 6.1 laporan).
Jalankan:  python benchmark.py     Hasil juga disimpan ke benchmark_results.csv
"""
import csv
import os
import time

import crypto_service as cs

SIZES = [("1 KB", 1024), ("100 KB", 100 * 1024), ("1 MB", 1024 ** 2), ("5 MB", 5 * 1024 ** 2), ("10 MB", 10 * 1024 ** 2)]
REPEAT = 5

sig_key, enc_key = cs.generate_rsa_key(), cs.generate_rsa_key()
sig_pub, enc_pub = cs.export_public_pem(sig_key), cs.export_public_pem(enc_key)

rows = []
print("%-8s %12s %12s %12s %12s  (ms, rata-rata %d kali)" % ("Ukuran", "Enkripsi", "Sign", "Verify", "Dekripsi", REPEAT))
for label, size in SIZES:
    data = os.urandom(size)
    acc = {"enc": 0, "sign": 0, "verify": 0, "dec": 0}
    for _ in range(REPEAT):
        t = time.perf_counter()
        pkg, tm = cs.build_package(data, "f.bin", "alice", "bob", enc_pub, sig_key)
        total_build = (time.perf_counter() - t) * 1000
        _p, _m, tm2 = cs.open_package(pkg, sig_pub, enc_key, "alice", "bob")
        acc["enc"] += tm["encrypt_aes"] + tm["wrap_key"]
        acc["sign"] += tm["sign"]
        acc["verify"] += tm2["verify"] + tm2["hash"]
        acc["dec"] += tm2["unwrap_key"] + tm2["decrypt_aes"]
    r = [label] + ["%.2f" % (acc[k] / REPEAT) for k in ("enc", "sign", "verify", "dec")]
    rows.append(r)
    print("%-8s %12s %12s %12s %12s" % tuple(r))

with open("benchmark_results.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["ukuran", "enkripsi_ms", "sign_ms", "verify_ms", "dekripsi_ms"])
    w.writerows(rows)
print("\nTersimpan di benchmark_results.csv")
