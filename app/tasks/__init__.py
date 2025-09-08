"""Utility package collecting asynchronous task functions.

Tasks are registered using :func:`register_task` and stored in :data:`TASKS`.
Importing this package loads the default tasks so that they are ready to use.
"""

from .registry import TASKS, register_task  # noqa: F401

# Import default tasks to populate TASKS on package import
from . import default_tasks  # noqa: F401

__all__ = ["TASKS", "register_task"]