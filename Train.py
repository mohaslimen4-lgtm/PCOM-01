import json
import os

import numpy as np
import pandas as pd
import xgboost as xgb

from features import TARGETS, build_features, package_name

CSV_PATH = "dataset.csv"
OUT_DIR = "Model"

PARAMS = dict(
    objective="count:poisson",
    n_estimators=1000,
    learning_rate=0.03,
    max_depth=5,
    subsample=0.7,
    colsample_bytree=0.5,
    reg_lambda=10.0,
    reg_alpha=1.0,
    random_state=42,
    n_jobs=-1,
    tree_method="hist",
)

df = pd.read_csv(CSV_PATH).drop_duplicates("purl").reset_index(drop=True)
groups = package_name(df["purl"])
weights = (1.0 / groups.map(groups.value_counts())).values        # every package counts equally

ref_date = pd.to_datetime(df["published_at"], errors="coerce", utc=True).max().tz_localize(None).normalize()
X = build_features(df, ref_date)

os.makedirs(OUT_DIR, exist_ok=True)
models = {}
for sev, col in TARGETS.items():
    y = df[col].fillna(0).astype(float).values
    # 5% of the weighted event count (max 3), so rare severities can still split their trees
    mcw = float(np.clip(0.05 * np.sum(weights * y), 1e-3, 3.0))
    model = xgb.XGBRegressor(**PARAMS, min_child_weight=mcw)
    model.fit(X, y, sample_weight=weights)
    models[sev] = f"xgb_ghsa_{sev}.json"
    model.save_model(os.path.join(OUT_DIR, models[sev]))
    print(f"{sev}: trained ({groups[y > 0].nunique()} positive packages)")

with open(os.path.join(OUT_DIR, "model_meta.json"), "w") as f:
    json.dump({"feature_columns": list(X.columns), "ref_date": str(ref_date.date()), "models": models}, f, indent=2)