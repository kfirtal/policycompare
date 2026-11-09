"""FMC functions: login, read all pages, resolve services, and build rules."""
import json
import time
from urllib.parse import quote, urlsplit
import requests
from rule import Rule, service_values, merge_services, network_literal, object_name, network_values, record_object


def connect(url, username, password, domain=None, verify=True, timeout=30):
    parts = urlsplit(url)
    if parts.scheme != 'https' or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment or parts.path.rstrip('/'):
        raise ValueError('FMC URL must be an HTTPS server origin')
    client = {'url': url.rstrip('/'), 'session': requests.Session(), 'verify': verify,
              'timeout': timeout, 'token': None, 'domain': domain, 'cache': {}}
    try:
        response = request(client, 'POST', '/api/fmc_platform/v1/auth/generatetoken', auth=(username, password))
        client['token'] = response.headers['X-auth-access-token']
        domains = json.loads(response.headers['DOMAINS'])
        if domain is None:
            if len(domains) != 1:
                raise ValueError('Multiple FMC domains: configure FMC_DOMAIN explicitly')
            client['domain'] = domains[0]['uuid']
        if not client['token'] or client['domain'] not in [d['uuid'] for d in domains]:
            raise ValueError('Invalid FMC token or domain')
        return client
    except Exception:
        close(client)
        raise


def close(client):
    client['token'] = None
    client['cache'].clear()
    client['session'].cookies.clear()
    client['session'].close()


def request(client, method, path, **kwargs):
    for attempt in range(3):
        try:
            response = client['session'].request(method, client['url'] + path,
                verify=client['verify'], timeout=client['timeout'], allow_redirects=False, **kwargs)
        except requests.RequestException:
            raise RuntimeError('FMC connection failed') from None
        if response.status_code == 429 and attempt < 2:
            time.sleep(5)
            continue
        if not 200 <= response.status_code < 300:
            raise RuntimeError(f'FMC returned HTTP {response.status_code}')
        return response


def get(client, path, **kwargs):
    path = '/api/fmc_config/v1/domain/' + quote(client['domain'], safe='') + path
    data = request(client, 'GET', path, headers={'X-auth-access-token': client['token']}, **kwargs).json()
    if not isinstance(data, dict):
        raise ValueError('Invalid FMC response')
    return data


def collection(client, path):
    """Read every page; stop on missing, repeated, or changing data."""
    result, seen, total = [], set(), None
    while True:
        data = get(client, path, params={'offset': len(result), 'limit': 1000, 'expanded': 'true'})
        items, paging = data['items'], data['paging']
        count = paging['count']
        if not isinstance(items, list) or type(count) is not int or count < 0:
            raise ValueError('Invalid FMC pagination')
        if total is not None and total != count:
            raise ValueError('FMC policy changed during collection')
        if 'offset' in paging and paging['offset'] != len(result):
            raise ValueError('Unexpected FMC page offset')
        total = count
        for item in items:
            identifier = item['id']
            if not identifier or identifier in seen:
                raise ValueError('Missing or repeated FMC item')
            seen.add(identifier)
        result.extend(items)
        if len(result) == total:
            return result
        if not items or len(result) > total:
            raise ValueError('Incomplete FMC collection')


def object_list(container, field):
    """Missing arrays mean no constraint; malformed arrays must never mean Any."""
    values = container.get(field, [])
    if not isinstance(values, list) or any(not isinstance(item, dict) for item in values):
        raise ValueError('Malformed FMC object array: ' + field)
    return values


def resolve_network(client, ref, stack=()):
    """Resolve a named network/group and every named nested member."""
    identifier, kind = ref['id'], ref['type']
    if identifier in stack:
        raise ValueError('Cyclic FMC network group')
    endpoints = {'Host': 'hosts', 'Network': 'networks', 'Range': 'ranges', 'NetworkGroup': 'networkgroups'}
    if kind not in endpoints:
        raise ValueError('Unsupported FMC network object')
    key = (kind, identifier)
    if key not in client['cache']:
        client['cache'][key] = get(client, '/object/' + endpoints[kind] + '/' + quote(identifier, safe=''))
    obj = client['cache'][key]
    if obj.get('id') != identifier or obj.get('type') != kind or obj.get('overrides') or obj.get('overridable'):
        raise ValueError('Invalid FMC network object or device override')
    if obj['name'] != ref['name']:
        raise ValueError('FMC object name changed during collection')
    values = []
    if kind == 'NetworkGroup':
        for member in object_list(obj, 'objects'):
            values.extend(resolve_network(client, member, stack + (identifier,)))
        if 'literals' in obj and 'literal' in obj:
            raise ValueError('Ambiguous FMC group literals')
        for literal in object_list(obj, 'literals' if 'literals' in obj else 'literal'):
            if literal['type'] not in ('Host', 'Network', 'Range'):
                raise ValueError('Unsupported FMC network literal')
            values.extend(network_values([literal['value']]))
    else:
        values.extend(network_values([obj['value']]))
    return record_object(client, 'network', obj['name'], values)


def network_names(client, raw, field):
    """Keep rule names and collect resolved object values for a separate report."""
    container = raw.get(field, {})
    if not isinstance(container, dict) or set(container) - {'objects', 'literals'}:
        raise ValueError('Unsupported FMC network field')
    names = []
    for ref in object_list(container, 'objects'):
        if ref['type'] not in ('Host', 'Network', 'Range', 'NetworkGroup'):
            raise ValueError('Unsupported FMC network object')
        names.append(object_name(ref['name']))
        resolve_network(client, ref)
    for literal in object_list(container, 'literals'):
        if literal['type'] not in ('Host', 'Network', 'Range'):
            raise ValueError('Unsupported FMC network literal')
        names.append(network_literal(literal['value']))
    return names or ['@any']


def resolve_service(client, ref, stack=()):
    identifier, kind = ref['id'], ref['type']
    if identifier in stack:
        raise ValueError('Cyclic FMC service group')
    endpoints = {'ProtocolPortObject': 'protocolportobjects', 'PortObjectGroup': 'portobjectgroups'}
    if kind not in endpoints:
        raise ValueError('Unsupported FMC service object')
    key = (kind, identifier)
    if key not in client['cache']:
        client['cache'][key] = get(client, '/object/' + endpoints[kind] + '/' + quote(identifier, safe=''))
    obj = client['cache'][key]
    if obj.get('id') != identifier or obj.get('type') != kind or obj.get('overrides') or obj.get('overridable'):
        raise ValueError('Invalid FMC service object or device override')
    if 'name' in ref and obj['name'] != ref['name']:
        raise ValueError('FMC object name changed during collection')
    if kind == 'ProtocolPortObject':
        if 'port' in obj and obj['port'] is None:
            raise ValueError('FMC service port is explicitly null')
        return record_object(client, 'service', obj['name'], service_values(obj['protocol'], obj.get('port')))
    result = []
    for member in object_list(obj, 'objects'):
        result.extend(resolve_service(client, member, stack + (identifier,)))
    if 'literals' in obj and 'literal' in obj:
        raise ValueError('Ambiguous FMC group literals')
    for literal in object_list(obj, 'literals' if 'literals' in obj else 'literal'):
        if literal['type'] != 'PortLiteral':
            raise ValueError('Unsupported FMC service literal')
        if 'port' in literal and literal['port'] is None:
            raise ValueError('FMC service port is explicitly null')
        result.extend(service_values(literal['protocol'], literal.get('port')))
    if not result:
        raise ValueError('Empty FMC service group')
    return record_object(client, 'service', obj['name'], result)


def policy_rules(client, name):
    policies = collection(client, '/policy/accesspolicies')
    matches = [p['id'] for p in policies if p['name'] == name]
    if len(matches) != 1:
        raise ValueError('FMC policy name must match exactly one policy')
    client['cache'].clear()
    rules = []
    for raw in collection(client, '/policy/accesspolicies/' + quote(matches[0], safe='') + '/accessrules'):
        client['objects'] = {}
        container = raw.get('destinationPorts', {})
        if not isinstance(container, dict) or set(container) - {'objects', 'literals'}:
            raise ValueError('Unsupported FMC service field')
        services = []
        for ref in object_list(container, 'objects'):
            services.extend(resolve_service(client, ref))
        for literal in object_list(container, 'literals'):
            if literal['type'] != 'PortLiteral':
                raise ValueError('Unsupported FMC service literal')
            if 'port' in literal and literal['port'] is None:
                raise ValueError('FMC service port is explicitly null')
            services.extend(service_values(literal['protocol'], literal.get('port')))
        rules.append(Rule(raw['id'], network_names(client, raw, 'sourceNetworks'),
                          network_names(client, raw, 'destinationNetworks'),
                          merge_services(services or [('any', 0, 65535)]), dict(client['objects'])))
    if not rules:
        raise ValueError('FMC policy is empty; review it manually')
    return rules
