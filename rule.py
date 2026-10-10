class Rule:
    def __init__(self, rule_number, source_objects, destination_objects,
                 destination_services):
        self.rule_number = rule_number
        self.source_objects = source_objects
        self.destination_objects = destination_objects
        self.destination_services = destination_services

    def __repr__(self):
        return (f"\n rule_number = {self.rule_number},\n"
                f" source_objects = {self.source_objects},\n"
                f" destination_objects = {self.destination_objects},\n"
                f" destination_services = {self.destination_services},\n")
