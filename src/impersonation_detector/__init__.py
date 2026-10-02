"""impersonation-detector: lookalike and impersonation detection for messaging platforms.

Layer 1 (this release): deterministic checks grounded in Unicode UTS #39 —
confusable skeletons, mixed-script detection, and edit distance against a set of
protected names (brands, domains, team names).
"""

from .lookalike import LookalikeDetector, Match
from .scripts import is_mixed_script, scripts_in
from .skeleton import confusable, skeleton

__all__ = [
    "LookalikeDetector",
    "Match",
    "confusable",
    "skeleton",
    "scripts_in",
    "is_mixed_script",
]
__version__ = "0.0.1"
