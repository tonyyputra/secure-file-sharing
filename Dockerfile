# syntax=docker/dockerfile:1

# ---------------------------------------------------------------- tahap 1: dependensi
# Tahap terpisah supaya roda (wheel) hasil kompilasi tidak membawa toolchain
# build ke image akhir.
FROM python:3.13-slim AS builder

WORKDIR /build
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt requirements-prod.txt ./
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements-prod.txt

# ---------------------------------------------------------------- tahap 2: runtime
FROM python:3.13-slim AS runtime

# PYTHONDONTWRITEBYTECODE: tidak ada __pycache__ di dalam container
# PYTHONUNBUFFERED  : log langsung tampil di docker compose logs
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    SFS_DATA_DIR=/app/data

COPY --from=builder /opt/venv /opt/venv

# Jalan sebagai pengguna biasa, bukan root. Aplikasi ini memproses berkas dan
# private key yang diunggah pengguna, jadi hak akses dibatasi sekecil mungkin.
RUN useradd --create-home --uid 10001 sfs
WORKDIR /app

COPY --chown=sfs:sfs app.py crypto_service.py ./
COPY --chown=sfs:sfs templates/ ./templates/
COPY --chown=sfs:sfs static/ ./static/

# Berkas uji dan benchmark ikut disertakan agar bisa dijalankan di dalam
# container: docker compose exec app python test_app.py
COPY --chown=sfs:sfs test_app.py benchmark.py seed.py ./

# Dibuat di sini supaya volume bernama mewarisi kepemilikan yang benar saat
# pertama kali dibuat.
RUN mkdir -p /app/data/packages && chown -R sfs:sfs /app/data

USER sfs
EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/login', timeout=4).status == 200 else 1)"]

# PENTING: satu worker saja.
#
# PENDING_KEYS (salinan private key selama 15 menit) dan LOGIN_ATTEMPTS
# (pembatas percobaan login) adalah dict di memori proses, bukan di basis
# data. Dengan lebih dari satu worker:
#   - unduhan private key setelah registrasi akan 404 secara acak, karena
#     permintaan bisa jatuh ke worker yang tidak menyimpan salinan itu;
#   - pembatas login menjadi N kali lebih lemah, satu hitungan per worker.
# Konkurensi diperoleh dari thread, bukan proses. SQLite aman di sini karena
# setiap permintaan membuka koneksinya sendiri (lihat get_db di app.py).
CMD ["gunicorn", "--bind", "0.0.0.0:5000", \
     "--workers", "1", \
     "--threads", "8", \
     "--timeout", "120", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "app:app"]
