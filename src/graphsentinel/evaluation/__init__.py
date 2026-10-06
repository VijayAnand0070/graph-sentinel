"""Evaluation protocol, metrics with uncertainty, and reproducible reporting."""

from graphsentinel.evaluation.metrics import (Comparison, Interval,
                                              OperatingPoint,
                                              average_precision,
                                              bootstrap_interval, describe,
                                              lift_over_base_rate,
                                              operating_point,
                                              paired_comparison,
                                              precision_at_k, recall_at_k,
                                              ranking_metrics, roc_auc,
                                              select_threshold_under_budget,
                                              threshold_at_budget,
                                              ThresholdSelection, brier_score)

__all__ = [
    "Comparison",
    "Interval",
    "OperatingPoint",
    "average_precision",
    "bootstrap_interval",
    "describe",
    "lift_over_base_rate",
    "operating_point",
    "paired_comparison",
    "precision_at_k",
    "ranking_metrics",
    "recall_at_k",
    "roc_auc",
    "select_threshold_under_budget",
    "ThresholdSelection",
    "brier_score",
    "threshold_at_budget",
]
