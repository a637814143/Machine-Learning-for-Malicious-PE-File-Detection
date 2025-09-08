# app/tasks/__init__.py
from .registry import TASKS, register_task  # noqa: F401

# Import default tasks to populate TASKS on package import
from . import default_tasks  # noqa: F401

__all__ = ["TASKS", "register_task"]