"""
dashboard_common.py
-------------------
Shared utilities for the SOC dashboard.
"""

import os
import subprocess
import sys
from pathlib import Path
import pandas as pd
import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import xai_engine as xe

PAGE_ICON = "🛡️"

RISK_COLORS = {
    "Low": "#1a7f37",      # Green
    "Medium": "#d29922",    # Orange
    "Critical": "#da3633",  # Red
}

REPO_ROOT = Path(__file__).parent.parent.parent


def _artifacts_missing():
    """Check for the specific files each module's training step produces."""
    checks = [
        REPO_ROOT / "module1" / "models" / "isolation_forest.pkl",
        REPO_ROOT / "module2" / "models" / "lightgbm_model.pkl",
        REPO_ROOT / "module3" / "data" / "unified_threat_data.csv",
    ]
    return [p for p in checks if not p.exists()]


def ensure_pipeline_built():
    """
    Streamlit Community Cloud (and any fresh clone) only runs
    `pip install` + `streamlit run` — it never runs train.py or
    build_dataset.py. Those generated artifacts are correctly gitignored
    (not source), which means a fresh deploy has no models and no dataset
    unless something builds them first. This does that once, transparently,
    on first load, instead of the dashboard hitting a dead-end
    "dataset is empty" error with no way to recover from the browser.
    """
    missing = _artifacts_missing()
    if not missing:
        return

    with st.spinner(
        "First-time setup: training models and building the dataset "
        "(only happens once per deployment, ~30-60 seconds)..."
    ):
        steps = [
            ("Module 1 (anomaly detection)", REPO_ROOT / "module1" / "src" / "train.py"),
            ("Module 2 (phishing classification)", REPO_ROOT / "module2" / "src" / "train.py"),
            ("Module 3 (unified dataset)", REPO_ROOT / "module3" / "src" / "build_dataset.py"),
        ]
        for label, script_path in steps:
            result = subprocess.run(
                [sys.executable, str(script_path)],
                cwd=str(script_path.parent),
                capture_output=True,
                text=True,
                timeout=600,
            )
            if result.returncode != 0:
                st.error(
                    f"First-time setup failed at {label}.\n\n"
                    f"stdout (last 2000 chars):\n{result.stdout[-2000:]}\n\n"
                    f"stderr (last 2000 chars):\n{result.stderr[-2000:]}"
                )
                st.stop()

    still_missing = _artifacts_missing()
    if still_missing:
        st.error(
            "Setup ran without error but expected files are still missing: "
            + ", ".join(str(p) for p in still_missing)
        )
        st.stop()

@st.cache_data(ttl=300)
def get_dataset():
    """
    Load unified threat dataset from module3/data/unified_threat_data.csv
    Returns empty DataFrame if file doesn't exist.
    """
    ensure_pipeline_built()
    data_path = Path(__file__).parent.parent / "data" / "unified_threat_data.csv"
    
    if not data_path.exists():
        return pd.DataFrame()
    
    try:
        df = pd.read_csv(data_path, parse_dates=["timestamp"])
        return df
    except Exception as e:
        st.error(f"Error loading dataset: {e}")
        return pd.DataFrame()


@st.cache_data(ttl=300)
def cached_global_feature_importance():
    """Cached wrapper around xai_engine.get_global_feature_importance() for the Explainability page."""
    return xe.get_global_feature_importance()


@st.cache_data(ttl=300)
def cached_local_shap(row_index: int):
    """Cached wrapper around xai_engine.get_local_shap_values() for one row's SHAP waterfall."""
    return xe.get_local_shap_values(row_index)


@st.cache_data(ttl=300)
def cached_dependence_data(feature: str):
    """Cached wrapper around xai_engine.get_dependence_data() for the SHAP dependence plots."""
    return xe.get_dependence_data(feature)


@st.cache_data(ttl=300)
def cached_lime_explanation(row_index: int):
    """Cached wrapper around xai_engine.get_lime_explanation() for the LIME panel."""
    return xe.get_lime_explanation(row_index)


@st.cache_data(ttl=300)
def shap_base_value():
    """Cached wrapper around xai_engine.get_shap_base_value() for the SHAP waterfall baseline."""
    return xe.get_shap_base_value()
