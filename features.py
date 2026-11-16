import re

import numpy as np
import pandas as pd

TARGETS = {
    "low":      "target_ghsa_low_count_90d",
    "moderate": "target_ghsa_moderate_count_90d",
    "high":     "target_ghsa_high_count_90d",
    "critical": "target_ghsa_critical_count_90d",
    "unknown":  "target_ghsa_unknown_count_90d",
}


def package_name(purl: pd.Series) -> pd.Series:
    return purl.astype(str).str.rsplit("@", n=1).str[0]


def build_features(df: pd.DataFrame, ref_date) -> pd.DataFrame:
    ref_date = pd.Timestamp(ref_date)
    drop_cols = list(TARGETS.values()) + ["purl"]
    X = df.drop(columns=drop_cols, errors="ignore").copy()

    # Timestamps -> age in days
    for c in ["created_at", "package_created_at", "published_at"]:
        if c in X:
            d = pd.to_datetime(X[c], errors="coerce", utc=True).dt.tz_localize(None)
            X[f"{c}_age_days"] = (ref_date - d).dt.days
            X = X.drop(columns=c)
    if "package_created_at_age_days" in X and "published_at_age_days" in X:
        X["created_to_published_days"] = X["package_created_at_age_days"] - X["published_at_age_days"]

    for c in list(X.columns):
        if pd.api.types.is_numeric_dtype(X[c]):
            continue
        conv = pd.to_numeric(X[c].astype(str).str.replace(r"[^\d.\-eE]", "", regex=True), errors="coerce")
        if re.search(r"_M\d+$", c) or conv.notna().mean() > 0.9:
            X[c] = conv
        else:
            X = X.drop(columns=c)

    # Summarise monthly snapshots (M0 = most recent)
    month_pat = re.compile(r"^(.*)_M(\d+)$")
    prefixes = sorted({m.group(1) for c in X.columns if (m := month_pat.match(c))})
    prefixes = [p for p in prefixes if "days_observed" not in p]

    def month_cols(prefix):
        cols = [c for c in X.columns if re.fullmatch(rf"{re.escape(prefix)}_M\d+", c)]
        return sorted(cols, key=lambda c: int(c.rsplit("_M", 1)[1]))

    agg = {}
    for p in prefixes:
        cols = month_cols(p)
        block = X[cols]
        agg[f"{p}_sum12"] = block.sum(axis=1)
        agg[f"{p}_mean12"] = block.mean(axis=1)
        agg[f"{p}_max12"] = block.max(axis=1)
        agg[f"{p}_last3_sum"] = block[cols[:3]].sum(axis=1)
        agg[f"{p}_prev3_sum"] = block[cols[3:6]].sum(axis=1)
        if len(cols) > 1:
            t = np.arange(len(cols))[::-1]
            agg[f"{p}_slope"] = np.polyfit(t, block.fillna(0).values.T, 1)[0]

    agg = pd.DataFrame(agg, index=X.index)
    ghsa_sum_cols = [c for c in agg if c.startswith("ghsa_") and c.endswith("_sum12")]
    agg["ghsa_total_12m"] = agg[ghsa_sum_cols].sum(axis=1)

    static_cols = [c for c in X.columns if not re.search(r"_M\d+$", c)]
    recent_cols = [c for c in X.columns if re.search(r"_M[0-2]$", c)]
    return pd.concat([X[static_cols + recent_cols], agg], axis=1).replace([np.inf, -np.inf], np.nan)
