# ThreatMatrix — Docker Setup Guide

## Folder Structure

```
threatmatrix-docker/
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── app/
│   └── main.py                  ← FastAPI inference service
└── models/
    ├── binary/                  ← copy your binary .pkl files here
    │   ├── model_ensemble.pkl
    │   ├── scaler.pkl
    │   └── feature_names.pkl
    └── multiclass/              ← copy your multiclass .pkl files here
        ├── model_ensemble_mc.pkl
        ├── scaler_mc.pkl
        ├── feature_names_mc.pkl
        └── label_encoder_mc.pkl
```

---

## Step 1 — Copy Your Model Files

From your Windows machine, copy the trained `.pkl` files:

```
# Binary models → models/binary/
threatmatrix_output/binary/model_ensemble.pkl
threatmatrix_output/binary/scaler.pkl
threatmatrix_output/binary/feature_names.pkl

# Multiclass models → models/multiclass/
threatmatrix_output/multiclass/model_ensemble_mc.pkl
threatmatrix_output/multiclass/scaler_mc.pkl
threatmatrix_output/multiclass/feature_names_mc.pkl
threatmatrix_output/multiclass/label_encoder_mc.pkl
```

---

## Step 2 — Build the Docker Image

```bash
cd threatmatrix-docker
docker build -t threatmatrix:latest .
```

First build takes ~5–10 mins (downloading PyTorch CPU). Subsequent builds are cached.

---

## Step 3 — Run with Docker Compose

```bash
docker compose up
```

Or run the ML service alone:

```bash
docker run --rm \
  -v $(pwd)/models/binary:/app/models/binary \
  -v $(pwd)/models/multiclass:/app/models/multiclass \
  -p 8000:8000 \
  threatmatrix:latest
```

---

## Step 4 — Test the API

**Health check:**
```bash
curl http://localhost:8000/health
```

**Full pipeline (Phase 1 → Phase 2):**
```bash
curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{
    "flows": [{
      "flow_duration": 1.5,
      "fwd_pkts_tot": 10,
      "bwd_pkts_tot": 8,
      "payload_bytes_per_second": 1200.0,
      "flow_pkts_per_sec": 12.0,
      "fwd_pkts_per_sec": 6.5,
      "bwd_pkts_per_sec": 5.5,
      "down_up_ratio": 0.8,
      "flow_FIN_flag_count": 1,
      "flow_SYN_flag_count": 1,
      "flow_RST_flag_count": 0,
      "flow_ACK_flag_count": 5
    }]
  }'
```

**Swagger UI** (interactive docs): http://localhost:8000/docs

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Check model load status |
| POST | `/predict` | Full pipeline: P1 → P2 |
| POST | `/predict/binary` | Phase 1 only |
| POST | `/predict/multiclass` | Phase 2 only |

---

## Calling from Your Backend

In your backend service (Node.js example):

```javascript
const ML_SERVICE_URL = process.env.ML_SERVICE_URL || "http://ml-service:8000";

async function classifyFlow(flowFeatures) {
  const response = await fetch(`${ML_SERVICE_URL}/predict`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ flows: [flowFeatures] })
  });
  const data = await response.json();
  return data.predictions[0];
}
```

In Python backend (requests):

```python
import requests

ML_URL = os.getenv("ML_SERVICE_URL", "http://ml-service:8000")

def classify_flow(flow_dict):
    resp = requests.post(f"{ML_URL}/predict", json={"flows": [flow_dict]}, timeout=5)
    resp.raise_for_status()
    return resp.json()["predictions"][0]
```

---

## Notes

- **No retraining needed** — the container loads pre-trained `.pkl` files at startup.
- **Models are mounted as volumes**, not baked into the image. This means you can update models without rebuilding.
- The ML service is on an **internal Docker network** and is not publicly exposed by default.
- For production, remove the `ports` mapping from `ml-service` in `docker-compose.yml`.
