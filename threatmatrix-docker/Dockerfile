# ============================================================
#  ThreatMatrix — ML Inference Service
#  Base: Python 3.12 slim
# ============================================================

FROM python:3.12-slim

# ── System dependencies ───────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# ── Working directory ─────────────────────────────────────────
WORKDIR /app

# ── Python dependencies ───────────────────────────────────────
# Copy requirements first for Docker layer caching
COPY requirements.txt .

# Install CPU-only torch (much smaller image, no CUDA needed for inference)
# Then install the rest
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir \
        torch==2.3.0 --index-url https://download.pytorch.org/whl/cpu && \
    pip install --no-cache-dir -r requirements.txt

# ── App code ──────────────────────────────────────────────────
COPY app/ ./app/

# ── Model directory structure ─────────────────────────────────
# Models are mounted at runtime via Docker volume.
# Structure expected:
#   /app/models/binary/       → model_ensemble.pkl, scaler.pkl
#   /app/models/multiclass/   → model_ensemble.pkl, scaler.pkl, feature_names.pkl
#   /app/models/anomaly/      → model_anomaly_detector.pkl, preprocessor_phase3.pkl
RUN mkdir -p /app/models/binary /app/models/multiclass /app/models/anomaly

# ── Non-root user for security ────────────────────────────────
RUN useradd -m -u 1000 threatmatrix && chown -R threatmatrix:threatmatrix /app
USER threatmatrix

# ── Expose port ───────────────────────────────────────────────
EXPOSE 8000

# ── Health check ──────────────────────────────────────────────
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# ── Start server ──────────────────────────────────────────────
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]