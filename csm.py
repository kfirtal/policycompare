"""CSM functions: explicit login, XML requests, complete policy collection."""
import time
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit
import requests
from rule import Rule, service_values, merge_services, network_literal, object_name, network_values, record_object


def connect(url, username, password, verify=True, timeout=30):
    parts = urlsplit(url)
    if parts.scheme != 'https' or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment or parts.path.rstrip('/') != '/nbi':
        raise ValueError('CSM URL must be HTTPS and end in /nbi')
    client = {'url': url.rstrip('/'), 'session': requests.Session(), 'verify': verify,
              'timeout': timeout, 'cookie': None, 'cache': {}}
    try:
        response, _ = call(client, '/login', 'loginRequest', {'username': username, 'password': password})
        client['cookie'] = response.cookies.get('asCookie')
        if not client['cookie']:
            raise ValueError('CSM login did not return a session cookie')
        return client
    except Exception:
        client['session'].close()
        raise


def close(client):
    try:
        if client['cookie']:
            call(client, '/logout', 'logoutRequest')
    finally:
        client['cookie'] = None
        client['cache'].clear()
        client['session'].cookies.clear()
        client['session'].close()


def call(client, path, root_name, fields=None):
    """Build XML safely, send it, and remove namespaces for simple lookups."""
    payload = ET.Element('{csm}' + root_name)
    for key, value in {'protVersion': '1.0', 'reqId': '1', **(fields or {})}.items():
        ET.SubElement(payload, key).text = str(value)
    headers = {'Content-Type': 'text/xml'}
    if client['cookie']:
        headers['Cookie'] = 'asCookie=' + client['cookie']
    for attempt in range(3):
        try:
            response = client['session'].post(client['url'] + path, data=ET.tostring(payload),
                headers=headers, verify=client['verify'], timeout=client['timeout'], allow_redirects=False)
        except requests.RequestException:
            raise RuntimeError('CSM connection failed') from None
        if response.status_code == 429 and attempt < 2:
            time.sleep(5)
            continue
        if not 200 <= response.status_code < 300:
            raise RuntimeError(f'CSM returned HTTP {response.status_code}')
        if '<!DOCTYPE' in response.text.upper() or '<!ENTITY' in response.text.upper():
            raise ValueError('XML entity declarations are unsupported')
        root = ET.fromstring(response.text)
        for node in root.iter():
            node.tag = node.tag.rsplit('}', 1)[-1]
        for field in ('networkObjectGIDs', 'serviceObjectGIDs', 'refGIDs'):
            references(root, './/' + field)
        if root.tag == 'error' or root.find('.//error') is not None:
            raise RuntimeError('CSM returned an API error')
        return response, root


def required(node, path):
    matches = node.findall(path)
    if len(matches) != 1 or len(matches[0]) or not (matches[0].text or '').strip():
        raise ValueError('Missing or ambiguous CSM field: ' + path)
    return matches[0].text.strip()


def references(node, path):
    """Accept a direct GID or nested <gid> entries; reject mixed formats."""
    result = []
    for container in node.findall(path):
        text = (container.text or '').strip()
        if len(container):
            if text or any(child.tag != 'gid' or (child.tail or '').strip() for child in container):
                raise ValueError('Malformed CSM reference list')
            result.extend(required(child, '.') for child in container)
        elif text:
            result.append(text)
    return result


def get_object(client, gid):
    if gid not in client['cache']:
        _, root = call(client, '/configservice/getPolicyObjectByGID', 'getPolicyObjectByGID', {'gid': gid})
        if root.find('.//overrideDetails') is not None:
            raise ValueError('CSM device overrides are unsupported')
        matches = [obj for obj in root.findall('./policyObject/*') if obj.findtext('gid') == gid]
        if len(matches) != 1:
            raise ValueError('CSM object could not be resolved')
        client['cache'][gid] = matches[0]
    return client['cache'][gid]


def port_list(client, gid, stack=()):
    if gid in stack:
        raise ValueError('Cyclic CSM port list')
    obj = get_object(client, gid)
    if obj.tag != 'portListPolicyObject':
        raise ValueError('Expected a CSM port list')
    result = []
    for ref in references(obj, 'refGIDs'):
        result.extend(port_list(client, ref, stack + (gid,)))
    starts, ends = obj.findall('startPort'), obj.findall('endPort')
    if len(starts) != len(ends):
        raise ValueError('Incomplete CSM port range')
    for first, last in zip(starts, ends):
        first_value = required(first, 'portNum') if len(first) else required(first, '.')
        last_value = required(last, 'portNum') if len(last) else required(last, '.')
        result.append(first_value + '-' + last_value)
    if not result:
        raise ValueError('Empty or unsupported CSM port list')
    return result


def service_parameter(client, param):
    if any(child.tag not in ('protocol', 'destinationPort', 'sourcePort', 'icmpMessage') for child in param):
        raise ValueError('Unsupported CSM service field')
    protocol = required(param, 'protocol')
    destinations = param.findall('destinationPort')
    if not destinations:
        return service_values(protocol)
    if len(destinations) != 1 or len(destinations[0]) != 1:
        raise ValueError('Ambiguous CSM destination port')
    choice = destinations[0][0]
    if choice.tag == 'port':
        return service_values(protocol, required(choice, '.'))
    if choice.tag not in ('portRefGID', 'portRef'):
        raise ValueError('Unsupported CSM destination port')
    result = []
    for ports in port_list(client, required(choice, '.')):
        result.extend(service_values(protocol, ports))
    return result


def resolve_service(client, gid, stack=()):
    if gid in stack:
        raise ValueError('Cyclic CSM service group')
    obj = get_object(client, gid)
    if obj.tag != 'servicePolicyObject':
        raise ValueError('Unsupported CSM service object')
    allowed = {'gid', 'name', 'lastUpdateTime', 'parentGID', 'type', 'comment', 'nodeGID',
               'isProperty', 'subType', 'isGroup', 'refGIDs', 'serviceParameters'}
    if any(child.tag not in allowed and (len(child) or (child.text or '').strip()) for child in obj):
        raise ValueError('Unrecognized CSM service object field')
    result = []
    for ref in references(obj, 'refGIDs'):
        result.extend(resolve_service(client, ref, stack + (gid,)))
    for param in obj.findall('serviceParameters'):
        result.extend(service_parameter(client, param))
    if not result:
        raise ValueError('Empty or unsupported CSM service object')
    return record_object(client, 'service', required(obj, 'name'), result)


def resolve_network(client, gid, stack=()):
    """Resolve group members recursively; a group name alone is not enough."""
    if gid in stack:
        raise ValueError('Cyclic CSM network group')
    obj = get_object(client, gid)
    if obj.tag != 'networkPolicyObject' or obj.find('fqdnData') is not None:
        raise ValueError('Unsupported CSM network object')
    allowed = {'gid', 'name', 'lastUpdateTime', 'parentGID', 'type', 'comment', 'nodeGID',
               'isProperty', 'subType', 'isGroup', 'refGIDs', 'ipv4Data', 'ipData'}
    if any(child.tag not in allowed and (len(child) or (child.text or '').strip()) for child in obj):
        raise ValueError('Unrecognized CSM network object field')
    values = []
    for ref in references(obj, 'refGIDs'):
        values.extend(resolve_network(client, ref, stack + (gid,)))
    literals = [required(item, '.') for item in obj.findall('ipv4Data') + obj.findall('ipData')]
    values.extend(network_values(literals))
    return record_object(client, 'network', required(obj, 'name'), values)


def network_names(client, raw, field):
    containers = raw.findall(field)
    if len(containers) != 1:
        raise ValueError('Missing or ambiguous CSM network field')
    container = containers[0]
    if any(child.tag not in ('networkObjectGIDs', 'ipv4Data', 'ipData') for child in container):
        raise ValueError('Unsupported CSM network constraint')
    names = []
    for ref in references(container, 'networkObjectGIDs'):
        obj = get_object(client, ref)
        if obj.tag != 'networkPolicyObject' or obj.find('fqdnData') is not None:
            raise ValueError('Unsupported CSM network object')
        names.append(object_name(required(obj, 'name')))
        resolve_network(client, ref)
    for literal in container.findall('ipv4Data') + container.findall('ipData'):
        names.append(network_literal(required(literal, '.')))
    return names or ['@any']


def policy_rows(client, name):
    """Collect all pages before comparing; a partial policy is an error."""
    fields = {'name': name, 'policyType': 'DeviceAccessRuleFirewallPolicy'}
    rows, seen, total = [], set(), None
    client['cache'].clear()
    while True:
        _, root = call(client, '/configservice/getPolicyConfigByName', 'policyConfigByNameRequest', fields)
        if root.tag != 'policyConfigDeviceResponse' or len(root.findall('policy')) != 1:
            raise ValueError('Invalid CSM policy response')
        if root.find('.//overrideDetails') is not None:
            raise ValueError('CSM device overrides are unsupported')
        for obj in root.findall('./policyObject/*'):
            gid = required(obj, 'gid')
            if gid in client['cache'] and ET.tostring(obj) != ET.tostring(client['cache'][gid]):
                raise ValueError('CSM object changed during collection')
            client['cache'][gid] = obj
        page = list(root.find('policy'))
        for raw in page:
            if raw.tag != 'deviceAccessRuleFirewallPolicy':
                raise ValueError('Unsupported CSM policy row')
            number = required(raw, 'orderId')
            if number in seen:
                raise ValueError('Repeated CSM rule')
            seen.add(number)
            rows.append(raw)
        end, count = root.findtext('endIndex'), root.findtext('totalCount')
        if end is None and count is None:
            if total is not None and len(rows) != total:
                raise ValueError('Incomplete CSM policy')
            return rows
        end, count = int(required(root, 'endIndex')), int(required(root, 'totalCount'))
        if end != len(rows) or count < end or (total is not None and count != total):
            raise ValueError('Inconsistent CSM pagination')
        total = count
        if len(rows) == total:
            return rows
        if not page:
            raise ValueError('Incomplete CSM policy')
        fields['startIndex'] = end


def policy_rules(client, name):
    rules = []
    for raw in policy_rows(client, name):
        client['objects'] = {}
        containers = raw.findall('services')
        if len(containers) != 1:
            raise ValueError('Missing or ambiguous CSM services')
        container = containers[0]
        if any(child.tag not in ('serviceObjectGIDs', 'serviceParameters') for child in container):
            raise ValueError('Unsupported CSM service field')
        services = []
        for ref in references(container, 'serviceObjectGIDs'):
            services.extend(resolve_service(client, ref))
        for param in container.findall('serviceParameters'):
            services.extend(service_parameter(client, param))
        rules.append(Rule(required(raw, 'orderId'), network_names(client, raw, 'sources'),
                          network_names(client, raw, 'destinations'),
                          merge_services(services or [('any', 0, 65535)]), dict(client['objects'])))
    if not rules:
        raise ValueError('CSM policy is empty; review it manually')
    return rules
