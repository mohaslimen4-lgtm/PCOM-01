import json
import os
import sys

import numpy as np
import pandas as pd
import xgboost as xgb

from features import build_features

MODEL_DIR = "Model"
IN_PATH = "data.csv"
OUT_PATH =  "predictions.csv"
OUTPUT = ["low", "moderate", "high", "critical"]

with open(os.path.join(MODEL_DIR, "model_meta.json")) as f:
    meta = json.load(f)

df = pd.read_csv(IN_PATH)
X = build_features(df, meta["ref_date"]).reindex(columns=meta["feature_columns"])

out = pd.DataFrame({"purl": df["purl"] if "purl" in df else np.arange(len(df))})
for sev in OUTPUT:
    model = xgb.XGBRegressor()
    model.load_model(os.path.join(MODEL_DIR, meta["models"][sev]))
    out[sev] = model.predict(X)

out.to_csv(OUT_PATH, index=False)
print(out.round(3).to_string(index=False, max_rows=30))
print(f"\nSaved {len(out)} predictions to {OUT_PATH}")