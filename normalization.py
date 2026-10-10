import ipaddress
from errors import ValidationError


def networks(values):
    parsed = []
    try:
        for value in values:
            value = str(value).strip()
            if '-' in value:
                a, b = [ipaddress.ip_address(x.strip()) for x in value.split('-')]
                parsed.extend(ipaddress.summarize_address_range(a, b))
            else:
                parsed.append(ipaddress.ip_network(value, strict=False))
        return frozenset(str(n) for version in (4, 6) for n in
                         ipaddress.collapse_addresses(x for x in parsed if x.version == version))
    except (ValueError, TypeError):
        raise ValidationError('Unsupported network value') from None


def ports(value):
    if value is None or str(value).lower() in ('any', ''):
        return ((0, 65535),)
    result = []
    try:
        for part in str(value).split(','):
            ends = part.strip().split('-')
            lo, hi = int(ends[0]), int(ends[-1])
            if len(ends) > 2 or not 0 <= lo <= hi <= 65535:
                raise ValueError()
            result.append((lo, hi))
    except ValueError:
        raise ValidationError('Unsupported port value') from None
    return tuple(result)


def service(protocol, port=None):
    proto = {'tcp': '6', 'udp': '17', 'ip': 'any', 'any': 'any'}.get(str(protocol).lower(), str(protocol))
    if proto == 'any' and port in (None, '', 'any'):
        return {('any', 0, 65535)}
    if proto not in ('6', '17'):
        raise ValidationError('Only IP-any, TCP and UDP are supported')
    return {(proto, lo, hi) for lo, hi in ports(port)}


def services(values):
    result = set()
    for value in values:
        if isinstance(value, tuple) and len(value) == 3:
            p, lo, hi = value
            result.update(service(p, f'{lo}-{hi}') if p != 'any' else service(p))
        else:
            result.update(('legacy', lo, hi) for lo, hi in ports(value))
    if ('any', 0, 65535) in result:
        return frozenset({('any', 0, 65535)})
    merged = []
    for p, lo, hi in sorted(result):
        if merged and merged[-1][0] == p and merged[-1][2] + 1 >= lo:
            old = merged.pop()
            merged.append((p, old[1], max(old[2], hi)))
        else:
            merged.append((p, lo, hi))
    return frozenset(merged)
