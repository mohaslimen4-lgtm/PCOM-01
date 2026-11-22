"""Feature construction shared by vuln_train.py and vuln_predict.py.

Same signal as the original v2 feature set (release age, 3m-vs-12m trends for
downloads and releases, historical / recent advisory totals), so results stay
comparable. Only difference: infinities are turned into NaN, which XGBoost handles.
"""
import numpy as np
import pandas as pd

SEVERITY_TARGETS = [
    "target_ghsa_low_count_90d",
    "target_ghsa_moderate_count_90d",
    "target_ghsa_high_count_90d",
    "target_ghsa_critical_count_90d",
    "target_ghsa_unknown_count_90d",
]

EXCLUDED_FROM_MODEL = ["purl", "package_created_at", "published_at"] + SEVERITY_TARGETS
SMALL = 1e-9


def purl_without_version(purl_col: pd.Series) -> pd.Series:
    """'pkg:npm/@scope/name@1.2.3?x=y' -> 'pkg:npm/@scope/name' (version/qualifiers removed)."""
    text = purl_col.astype(str).str.split("#").str[0].str.split("?").str[0]
    return text.str.rsplit("@", n=1).str[0]


def _window_cols(frame: pd.DataFrame, stem: str, n_months: int) -> list:
    return [f"{stem}_M{m}" for m in range(n_months) if f"{stem}_M{m}" in frame.columns]


def _add_trend_block(frame: pd.DataFrame, stem: str, label: str) -> None:
    """Adds last-3-month mean, 12-month mean and their ratio for a monthly series."""
    year_cols = _window_cols(frame, stem, 12)
    quarter_cols = _window_cols(frame, stem, 3)
    if year_cols and quarter_cols:
        frame[f"{label}_last3_mean"] = frame[quarter_cols].mean(axis=1)
        frame[f"{label}_last12_mean"] = frame[year_cols].mean(axis=1)
        frame[f"{label}_trend_ratio"] = frame[f"{label}_last3_mean"] / (frame[f"{label}_last12_mean"] + SMALL)


def build_model_inputs(raw: pd.DataFrame) -> pd.DataFrame:
    """Raw package/version rows -> numeric feature table (no ids, no targets)."""
    work = raw.copy()

    # Age of the package when this version was published (days)
    born = pd.to_datetime(work["package_created_at"], errors="coerce", utc=True)
    released = pd.to_datetime(work["published_at"], errors="coerce", utc=True)
    work["age_at_release_days"] = (released - born).dt.total_seconds() / 86400.0

    # Trend features
    _add_trend_block(work, "package_downloads", "dl")
    _add_trend_block(work, "package_stable_release_count", "rel")

    # Advisory history
    lifetime_cols = [
        c for c in ["ghsa_low_count", "ghsa_moderate_count", "ghsa_high_count",
                    "ghsa_critical_count", "ghsa_unknown_count"]
        if c in work.columns
    ]
    if lifetime_cols:
        work["advisories_lifetime_total"] = work[lifetime_cols].sum(axis=1)

    last_quarter_cols = [
        c for c in work.columns
        if c.startswith("ghsa_") and any(c.endswith(f"_M{m}") for m in range(3))
    ]
    if last_quarter_cols:
        work["advisories_last3_total"] = work[last_quarter_cols].sum(axis=1)

    keep = [c for c in work.columns if c not in EXCLUDED_FROM_MODEL]
    table = work[keep].apply(pd.to_numeric, errors="coerce")
    return table.replace([np.inf, -np.inf], np.nan)