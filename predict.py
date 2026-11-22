
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


def predict(rows: pd.DataFrame) -> pd.DataFrame:
    """DataFrame in (one or more versions of a package) -> one-row DataFrame out:
    one predicted rate per severity, plus 'purl' when the input has it."""
    if rows is None or rows.empty:
        raise ValueError("Input DataFrame is empty.")

    bundle = _load_bundle()
    row = select_row(rows.reset_index(drop=True))
    X = build_model_inputs(row).reindex(columns=bundle["input_columns"])

    record = {c: row[c].iloc[0] for c in ("purl",) if c in row.columns}  # purl is optional
    for target in SEVERITY_TARGETS:
        rate = float(bundle["models"][target].predict(X)[0])
        record[target] = round(max(rate, MIN_RATE), 8)
    return pd.DataFrame([record])


if __name__ == "__main__":
    result = predict(pd.read_csv(sys.argv[1] if len(sys.argv) > 1 else "xz.csv"))
    result.to_csv(sys.argv[2] if len(sys.argv) > 2 else "result.csv", index=False)
    for target in SEVERITY_TARGETS:
        rate = float(result[target].iloc[0])
        print(f"{target:32s} {rate:.6f} | {poisson_breakdown(rate)}")