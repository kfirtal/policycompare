class Rule:
    def __init__(self, rule_number, source_objects, destination_objects,
                 destination_services, action='ALLOW', enabled=True,
                 object_values=None, issues=()):
        self.rule_number = rule_number
        self.source_objects = source_objects
        self.destination_objects = destination_objects
        self.destination_services = destination_services
        self.action = action
        self.enabled = enabled
        # Only None means "not supplied"; malformed values must reach validation.
        self.object_values = {} if object_values is None else object_values
        self.issues = tuple(issues)

    def __repr__(self):
        return f'Rule({self.rule_number!r}, {self.action}, {self.source_objects!r}, {self.destination_objects!r}, {self.destination_services!r})'
