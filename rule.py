from errors import ValidationError
from normalization import networks, services


def record_object(inventory, errors, name, kind, values):
    """Keep only real named references; literal values never enter this inventory."""
    if not isinstance(name, str) or not name.strip() or name.startswith('@'):
        errors.append('Referenced object has no usable name')
        return
    canonical = networks(values) if kind == 'network' else services(values) if kind == 'service' else frozenset(values)
    record = dict(name=name, kind=kind, values=sorted(canonical))
    key = (kind, name)
    if key in inventory and inventory[key] != record:
        raise ValidationError('Conflicting values for the same object name')
    inventory[key] = record


class Rule:
    def __init__(self, rule_number, source_objects, destination_objects,
                 destination_services, action='ALLOW', enabled=True,
                 object_values=None, issues=(), referenced_objects=None,
                 service_objects=(), object_issues=()):
        self.rule_number = rule_number
        self.source_objects = source_objects
        self.destination_objects = destination_objects
        self.destination_services = destination_services
        self.action = action
        self.enabled = enabled
        # Only None means "not supplied"; malformed values must reach validation.
        self.object_values = {} if object_values is None else object_values
        self.issues = tuple(issues)
        # Full inventory includes groups and every named nested member.
        # None means unavailable; [] means successfully collected, no references.
        self.referenced_objects = referenced_objects
        self.service_objects = list(service_objects)
        self.object_issues = tuple(object_issues)

    def __repr__(self):
        return f'Rule({self.rule_number!r}, {self.action}, {self.source_objects!r}, {self.destination_objects!r}, {self.destination_services!r})'
