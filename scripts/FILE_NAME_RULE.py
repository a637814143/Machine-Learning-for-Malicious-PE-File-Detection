import inspect
from datetime import datetime


def get_current_function_name():
    stack = inspect.stack()
    function_name = stack[1].function
    return function_name


def get_timestamp():
    return datetime.now().strftime("%Y-%m-%d-%H:%M")


def GET_NAME():
    function_name = get_current_function_name()
    timestamp = get_timestamp()
    return f"{function_name}_{timestamp}"
