"""A versioned heuristic calculated exclusively from persisted session evidence."""

from __future__ import annotations

import math
from collections.abc import Mapping

VERSION = "dsof-observed-engagement-v1"
DEFAULT_WEIGHTS = {
    "duration_seconds": 0.30,
    "interaction_count": 0.30,
    "distinct_actions": 0.20,
    "max_depth": 0.20,
}
DEFAULT_NORMALIZERS = {
    "duration_seconds": 120.0,
    "interaction_count": 20.0,
    "distinct_actions": 5.0,
    "max_depth": 4.0,
}


def validate_policy(weights=None, normalizers=None):
    """Return independent validated policy copies; refuse ambiguous policies."""
    weights = dict(DEFAULT_WEIGHTS if weights is None else weights)
    normalizers = dict(DEFAULT_NORMALIZERS if normalizers is None else normalizers)
    keys = set(DEFAULT_WEIGHTS)
    if set(weights) != keys or set(normalizers) != keys:
        raise ValueError("DSI weights and normalizers must name all four evidence inputs")
    for label, values in (("weights", weights), ("normalizers", normalizers)):
        for key, value in values.items():
            if isinstance(value, bool) or not isinstance(value, (float, int)) or not math.isfinite(value):
                raise ValueError(f"DSI {label}.{key} must be a finite number")
            if value < 0 or (label == "normalizers" and value == 0):
                raise ValueError(f"DSI {label}.{key} is outside its valid range")
    if not math.isclose(sum(weights.values()), 1.0, abs_tol=1e-9):
        raise ValueError("DSI weights must sum to 1")
    return weights, normalizers


def calculate_dsi(inputs: Mapping, *, provisional=False, weights=None, normalizers=None):
    """Score measured evidence, keeping the exact inputs and policy reproducible.

    Missing evidence produces no score. Invalid supplied evidence is an error;
    neither case is silently converted to invented zero-valued observations.
    """
    weights, normalizers = validate_policy(weights, normalizers)
    observed = {key: inputs[key] for key in DEFAULT_WEIGHTS if key in inputs}
    for key, value in observed.items():
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
            raise ValueError(f"DSI {key} must be a finite nonnegative number")
        if key != "duration_seconds" and int(value) != value:
            raise ValueError(f"DSI {key} must be an integer count")
    result = {
        "version": VERSION,
        "kind": "observed-session heuristic",
        "score": None,
        "inputs": observed,
        "weights": weights,
        "normalizers": normalizers,
        "provisional": bool(provisional),
        "bounds": [0, 100],
    }
    missing = [key for key in DEFAULT_WEIGHTS if key not in observed]
    if missing:
        result["reason"] = "incomplete_evidence"
        result["missing_inputs"] = missing
        return result
    if observed["distinct_actions"] > observed["interaction_count"]:
        raise ValueError("DSI distinct_actions cannot exceed interaction_count")
    if observed["interaction_count"] == 0 and (observed["distinct_actions"] or observed["max_depth"]):
        raise ValueError("DSI action evidence requires at least one interaction")
    normalized = {key: min(observed[key] / normalizers[key], 1.0) for key in weights}
    result["normalized"] = normalized
    result["score"] = round(100 * sum(weights[key] * normalized[key] for key in weights), 4)
    return result


def score_session(session: Mapping, *, provisional=None, weights=None, normalizers=None):
    """Convenience entry point for persisted session records."""
    if provisional is None:
        provisional = session.get("state") == "active"
    return calculate_dsi(session, provisional=provisional, weights=weights, normalizers=normalizers)
