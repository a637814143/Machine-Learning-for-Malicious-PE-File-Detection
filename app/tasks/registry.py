from typing import Callable, Dict, Tuple

TaskFunc = Callable[[Tuple, Callable[[int], None], Callable[[str], None]], None]

TASKS: Dict[str, TaskFunc] = {}


def register_task(name: str):
    def decorator(func: TaskFunc) -> TaskFunc:
        TASKS[name] = func
        return func

    return decorator
