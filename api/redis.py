from django.core.cache import cache
import json

TIME_LIMIT = 120


def setCache(key, value, tl=TIME_LIMIT):
    if isinstance(value, (dict, list)):
        value = json.dump(value)

    cache.set(key, value, timeout=tl)


def getCache(key):
    value = cache.get(key)

    if value is None:
        return None

    try:
        return json.load(value)
    except (TypeError, json.JSONDecodeError):
        return value
