"""Task registry for UI asynchronous functions."""
from typing import Callable, Dict, Tuple

# Type alias for task functions. The function receives:
#  args: a tuple of parameters from the UI
#  progress_callback: callable accepting int 0-100
#  text_callback: callable accepting str (plain text or HTML)
TaskFunc = Callable[[Tuple, Callable[[int], None], Callable[[str], None]], None]

# Global registry mapping task names to functions.
TASKS: Dict[str, TaskFunc] = {}

def register_task(name: str):
    """Decorator to register a task function.

    Usage:
        @register_task("任务名称")
        def my_task(args, progress, text):
            ...
    """
    def decorator(func: TaskFunc) -> TaskFunc:
        TASKS[name] = func
        return func
    return decorator