from typing import Any


def safe_get(data: dict, *keys, default_value: Any = None):
    try:
        for key in keys:
            data = data[key]

        return data
    except KeyError:
        return default_value

