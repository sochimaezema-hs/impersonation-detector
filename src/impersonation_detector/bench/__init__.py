"""Layer 4: a reproducible benchmark of impersonation and phishing messages, with
label-preserving adversarial variants and per-layer metrics."""

from .run import Report, run_benchmark
from .seed import load_seed
from .variants import VARIANTS, apply_variant

__all__ = ["VARIANTS", "Report", "apply_variant", "load_seed", "run_benchmark"]
