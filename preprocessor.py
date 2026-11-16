"""Compatibility shim for artifacts pickled with ``training`` on ``sys.path``.

Older Isolation Forest and preprocessing bundles reference the top-level module
name ``preprocessor`` because their training scripts ran with ``training/`` on
``sys.path``. The canonical implementation lives in ``training/preprocessor.py``.
Keeping this re-export at the repository root lets those artifacts unpickle
without changing the stored bytes or the serving model.

New code should import from ``training.preprocessor``.
"""

from training.preprocessor import (  # noqa: F401
    IDENTIFIER_COLUMNS,
    FlowSanitizer,
    build_leak_free_pipeline,
)

__all__ = ["IDENTIFIER_COLUMNS", "FlowSanitizer", "build_leak_free_pipeline"]
