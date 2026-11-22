from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel
import requests
import pandas as pd
import io
import uvicorn
import math
import re
import sys

import joblib
import pandas as pd

from features import SEVERITY_TARGETS, build_model_inputs

ARTIFACT_FILE = "Model/vuln_count_models.joblib"
MIN_RATE = 1e-8  # never exactly 0


def version_text(rows):
    """Version per row: 'version' column if present, else the part after '@' in purl."""
    if "version" in rows.columns:
        return rows["version"].astype(str)
    if "purl" in rows.columns:
        return rows["purl"].astype(str).str.extract(r"@([^?#]+)", expand=False)
    return pd.Series([None] * len(rows), index=rows.index)


def semver_key(text):
    """'1.2.3' -> (stable, 1, 2, 3); pre-releases (2.0.0-beta) rank below stable; junk -> None."""
    m = re.match(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(.*)$", str(text).strip())
    if not m:
        return None
    major, minor, patch, rest = m.groups()
    return (not re.search(r"[A-Za-z]", rest), int(major), int(minor or 0), int(patch or 0))


def select_row(rows):
    keys = [semver_key(v) for v in version_text(rows)]
    valid = [i for i, k in enumerate(keys) if k]
    if valid:
        best = max(keys[i] for i in valid)
        tied = [i for i in valid if keys[i] == best]
    else:
        tied = list(range(len(rows)))
    dates = pd.to_datetime(rows.iloc[tied].get("published_at", pd.Series(index=rows.index[tied], dtype=object)),
                           errors="coerce", utc=True)
    pos = tied[int(dates.reset_index(drop=True).idxmax())] if dates.notna().any() else tied[-1]
    return rows.iloc[[pos]]


def poisson_breakdown(lam):
    p = [math.exp(k * math.log(lam) - lam - math.lgamma(k + 1)) * 100 for k in range(3)]
    return f"P(0)={p[0]:5.1f}%  P(1)={p[1]:5.1f}%  P(2)={p[2]:5.1f}%  P(>=3)={max(0, 100 - sum(p)):5.1f}%"


_BUNDLE = None


def _load_bundle():
    global _BUNDLE
    if _BUNDLE is None:                      # load the models once, reuse on later calls
        _BUNDLE = joblib.load(ARTIFACT_FILE)
    return _BUNDLE


app = FastAPI(title="ML Prediction API")


class EvaluationBody(BaseModel):
    testdata_download_endpoint: str
    prediction_upload_endpoint: str


def run_model(df: pd.DataFrame) -> pd.DataFrame:
    # ==== EXAMPLE: ADD YOUR PREDICTIONS OF TRAINED MODEL HERE ====
    # df contains the input time-series metrics for a package (multiple rows).
    # Return a single-row DataFrame containing the target columns required by the competition:
  
    if df is None or df.empty:
        raise ValueError("Input DataFrame is empty.")

    bundle = _load_bundle()
    row = select_row(df.reset_index(drop=True))
    X = build_model_inputs(row).reindex(columns=bundle["input_columns"])

    record = {c: row[c].iloc[0] for c in ("purl",) if c in row.columns}  # purl is optional
    for target in SEVERITY_TARGETS:
        rate = float(bundle["models"][target].predict(X)[0])
        record[target] = round(max(rate, MIN_RATE), 8)
    prediction_df =  pd.DataFrame([record])   
    # =============================================================

    return prediction_df


def start_prediction(download_url: str, upload_url: str):
    try:
        result = requests.get(download_url, timeout=30)
        result.raise_for_status()

        # Read input time-series CSV (comma-separated, US float format)
        input_data = pd.read_csv(io.StringIO(result.text), sep=",", decimal=".")

        # ADD YOUR PREDICTION MODEL HERE TO PREDICT A SINGLE ROW WITH THE TARGET HEADERS
        # ======== Example =========
        prediction_data = run_model(input_data)
        # ======== END Example =====

        assert len(prediction_data) == 1, "Prediction DataFrame must contain exactly 1 row"
        output_buffer = io.StringIO()
        prediction_data.to_csv(output_buffer, sep=",", decimal=".", header=True, index=False)
        output_buffer.seek(0)

        file = {"predictions": ("prediction.csv", output_buffer.getvalue(), "text/csv")}

        upload_res = requests.post(upload_url, files=file, timeout=30)
        upload_res.raise_for_status()
        print("Evaluation Result:", upload_res.json())

    except Exception as e:
        print("Error:", e)


@app.post("/predict", status_code=200)
async def prediction(payload: EvaluationBody, background_tasks: BackgroundTasks):
    # Start prediction in background
    background_tasks.add_task(
        start_prediction,
        payload.testdata_download_endpoint,
        payload.prediction_upload_endpoint,
    )
    return {"status": "prediction started"}


@app.get("/health", status_code=200)
async def health():
    return {"health": "up"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)