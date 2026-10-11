"""Small shape checks shared by JSON API readers.

Missing optional arrays are empty. Explicit nulls, strings and objects are not
arrays: accepting them can silently drop a filtering condition.
"""
from errors import ValidationError


def object_array(container, field):
    value = container.get(field, [])
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise ValidationError('Expected an array of objects: ' + field)
    return value


def identifier(value):
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ValidationError('Expected a nonempty string identifier')
    return value
