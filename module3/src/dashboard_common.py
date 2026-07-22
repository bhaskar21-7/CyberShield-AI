"""
dashboard_common.py
-------------------
Shared utilities for the SOC dashboard.
"""

import os
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

@st.cache_data(ttl=300)
def get_dataset():
    """
    Load unified threat dataset from module3/data/unified_threat_data.csv
    Returns empty DataFrame if file doesn't exist.
    """
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
