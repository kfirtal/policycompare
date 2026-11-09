"""A rule and the small formatting helpers shared by both readers."""
import ipaddress


class Rule:
    def __init__(self, rule_number, source_objects, destination_objects, destination_services,
                 referenced_objects=None):
        self.rule_number = rule_number
        self.source_objects = source_objects
        self.destination_objects = destination_objects
        self.destination_services = destination_services
        # Keys are (kind, name); values include named nested group members.
        # None means values were not collected, not that the inventory is empty.
        self.referenced_objects = referenced_objects

    def signature(self):
        return (frozenset(self.source_objects), frozenset(self.destination_objects),
                frozenset(self.destination_services))

    def __repr__(self):
        return (f'Rule {self.rule_number}: sources={self.source_objects}, '
                f'destinations={self.destination_objects}, services={self.destination_services}')


def service_values(protocol, port=None):
    """Represent TCP/UDP services as (protocol, first_port, last_port)."""
    protocol = {'6': 'tcp', '17': 'udp', 'ip': 'any'}.get(str(protocol).lower(), str(protocol).lower())
    if protocol == 'any' and port in (None, '', 'any'):
        return [('any', 0, 65535)]
    if protocol not in ('tcp', 'udp'):
        raise ValueError('Only TCP, UDP and IP-any services are supported')
    if port is None or str(port).lower() == 'any':
        return [(protocol, 0, 65535)]
    result = []
    for part in str(port).split(','):
        ends = part.strip().split('-')
        if len(ends) not in (1, 2):
            raise ValueError('Invalid port range')
        first, last = int(ends[0]), int(ends[-1])
        if not 0 <= first <= last <= 65535:
            raise ValueError('Invalid port range')
        result.append((protocol, first, last))
    return result


def merge_services(values):
    """Make 80,81 and 80-81 compare equally without expanding every port."""
    if ('any', 0, 65535) in values:
        return [('any', 0, 65535)]
    merged = []
    for protocol, first, last in sorted(set(values)):
        if merged and merged[-1][0] == protocol and first <= merged[-1][2] + 1:
            previous = merged.pop()
            merged.append((protocol, previous[1], max(previous[2], last)))
        else:
            merged.append((protocol, first, last))
    return merged


def network_literal(value):
    """Keep literal addresses distinct from named objects and Any."""
    return '@literal:' + ','.join(network_values([value]))


def network_values(values):
    """Compare equivalent hosts, subnets and ranges in one canonical form."""
    parsed = []
    for value in values:
        value = str(value).strip()
        if '-' in value:
            first, last = [ipaddress.ip_address(part.strip()) for part in value.split('-')]
            parsed.extend(ipaddress.summarize_address_range(first, last))
        else:
            parsed.append(ipaddress.ip_network(value, strict=False))
    return tuple(str(net) for version in (4, 6) for net in
                 ipaddress.collapse_addresses(n for n in parsed if n.version == version))


def record_object(client, kind, name, values):
    """Remember each referenced object's values; reject conflicting names."""
    key = (kind, object_name(name))
    canonical = network_values(values) if kind == 'network' else tuple(merge_services(values))
    if not canonical:
        raise ValueError('Referenced object has no resolved values')
    inventory = client.setdefault('objects', {})
    if key in inventory and inventory[key] != canonical:
        raise ValueError('Same object name has conflicting values')
    inventory[key] = canonical
    return canonical


def object_name(value):
    if not isinstance(value, str) or not value.strip() or value.startswith('@'):
        raise ValueError('Missing or reserved object name')
    return value
