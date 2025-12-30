from django.core.cache import cache
import json

TIME_LIMIT = 120


def setcache(key, value, tl=TIME_LIMIT):
    if isinstance(value, (dict, list)):
        value = json.dump(value)

    cache.set(key, value, timeout=tl)


def setSignup(key, value, tl=TIME_LIMIT):
    if isinstance(value, (dict, list)):
        value = json.dump(value)

    cache.set(key, value, timeout=tl)


def get(key):
    value = cache.get(key)

    if value is None:
        return None

    try:
        return json.load(value)
    except (TypeError, json.JSONDecodeError):
        return value
