
import os

import joblib
import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.metrics import mean_absolute_error
from sklearn.model_selection import GroupShuffleSplit

from features import SEVERITY_TARGETS, build_model_inputs, purl_without_version

DATA_FILE = "dataset.csv"
ARTIFACT_FILE = "Model/vuln_count_models.joblib"


def make_model(start_rate: float) -> xgb.XGBRegressor:
    return xgb.XGBRegressor(
        objective="count:poisson",
        n_estimators=120,
        max_depth=4,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        base_score=start_rate,   # > 0 so count:poisson works even if a target is all zeros
        random_state=42,
    )


def run_training():
    raw = pd.read_csv(DATA_FILE)
    table = build_model_inputs(raw)          # all columns kept, same as v2
    input_columns = list(table.columns)


    pkg_ids = purl_without_version(raw["purl"])
    splitter = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=42)
    fit_pos, hold_pos = next(splitter.split(raw, groups=pkg_ids))
    print(f"Validation split -> fit rows: {len(fit_pos)}, holdout rows: {len(hold_pos)}")

    models = {}
    for target in SEVERITY_TARGETS:
        y = raw[target].fillna(0).astype(float).clip(lower=0)

        check = make_model(max(float(y.iloc[fit_pos].mean()), 1e-5))
        check.fit(table.iloc[fit_pos], y.iloc[fit_pos])
        pred = np.clip(check.predict(table.iloc[hold_pos]), 0, None)
        base = np.full(len(hold_pos), y.iloc[fit_pos].mean())
        print(f"{target}: holdout MAE={mean_absolute_error(y.iloc[hold_pos], pred):.4f} "
              f"(baseline {mean_absolute_error(y.iloc[hold_pos], base):.4f})")
        tr = np.clip(check.predict(table.iloc[fit_pos]), 0, None)
        print(f"   train MAE={mean_absolute_error(y.iloc[fit_pos], tr):.4f}")
        # ---- final model: all rows ----
        final = make_model(max(float(y.mean()), 1e-5))
        final.fit(table, y)
        models[target] = final

    os.makedirs(os.path.dirname(ARTIFACT_FILE), exist_ok=True)
    joblib.dump({"models": models, "input_columns": input_columns}, ARTIFACT_FILE)
    print(f"\nSaved all-rows models -> {ARTIFACT_FILE}")


if __name__ == "__main__":
    run_training()