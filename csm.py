"""CSM 4.25 NBI reader; no import-time authentication or requests."""
import xml.etree.ElementTree as ET
from transport import Transport
from errors import APIError, ValidationError
from normalization import networks, service
from rule import Rule, record_object


def parse_xml(text):
    if '<!DOCTYPE' in text.upper() or '<!ENTITY' in text.upper():
        raise ValidationError('XML entities are not supported')
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        raise ValidationError('Invalid CSM XML') from None
    for node in root.iter():
        node.tag = node.tag.rsplit('}', 1)[-1]
    if root.tag == 'error' or root.find('.//error') is not None:
        raise APIError('CSM returned an application error')
    for node in root.iter():
        if node.tag in ('networkObjectGIDs', 'serviceObjectGIDs', 'refGIDs'):
            if (node.text or '').strip() or any(child.tag != 'gid' for child in node):
                raise ValidationError('Invalid CSM reference list')
    return root


def required(node, path):
    matches = node.findall(path)
    if len(matches) != 1 or len(matches[0]):
        raise ValidationError('Expected exactly one scalar CSM field: ' + path)
    value = matches[0].text
    if value is None or not value.strip():
        raise ValidationError('Missing CSM field: ' + path)
    return value.strip()


class CSMClient(Transport):
    def __init__(self, base_url, **kwargs):
        super().__init__(base_url, **kwargs)
        self.cookie, self.cache = None, {}
        self.referenced_objects, self.object_issues = {}, []

    def call(self, path, root_name, fields=None):
        root = ET.Element('{' + 'csm' + '}' + root_name)
        for key, value in {'protVersion': '1.0', 'reqId': '1', **(fields or {})}.items():
            ET.SubElement(root, key).text = str(value)
        headers = {'Content-Type': 'text/xml'}
        if self.cookie:
            headers['Cookie'] = 'asCookie=' + self.cookie
        response = self.request('POST', path, data=ET.tostring(root, encoding='utf-8'), headers=headers)
        return response, parse_xml(response.text)

    def login(self, username, password):
        self.cookie = None
        self.cache.clear()
        response, _ = self.call('/login', 'loginRequest', {'username': username, 'password': password})
        self.cookie = response.cookies.get('asCookie')
        if not self.cookie:
            raise APIError('CSM login did not return a session cookie')
        self.cache.clear()

    def logout(self):
        if self.cookie:
            try:
                self.call('/logout', 'logoutRequest')
            finally:
                self.cookie = None
                self.cache.clear()

    def close(self):
        """Attempt server logout; always release local credentials and caches."""
        try:
            self.logout()
        finally:
            self.cookie = None
            self.cache.clear()
            self.referenced_objects.clear()
            self.object_issues.clear()
            super().close()

    def query(self, endpoint, root, fields):
        if not self.cookie:
            raise APIError('CSM login required')
        return self.call('/configservice/' + endpoint, root, fields)[1]

    def getGIDByName(self, name):
        return required(self.query('getDeviceConfigByName', 'deviceConfigByNameRequest', {'name': name}), './/gid')

    def getPolicyList(self, gid):
        return ET.tostring(self.query('getPolicyListByDeviceGID', 'policyListByDeviceGIDRequest', {'gid': gid}), encoding='unicode')

    def object(self, gid):
        if gid not in self.cache:
            root = self.query('getPolicyObjectByGID', 'getPolicyObjectByGID', {'gid': gid})
            if root.find('overrideDetails') is not None:
                raise ValidationError('CSM device overrides require explicit resolution')
            candidates = [n for n in root.findall('./policyObject/*') if n.findtext('gid') == gid]
            if len(candidates) != 1:
                raise ValidationError('Unresolved CSM object')
            self.cache[gid] = candidates[0]
        return self.cache[gid]

    def resolve(self, gid, kind, stack=()):
        if gid in stack:
            raise ValidationError('Cyclic CSM object group')
        obj = self.object(gid)
        expected = 'networkPolicyObject' if kind == 'network' else 'servicePolicyObject'
        if obj.tag != expected:
            raise ValidationError('Unexpected CSM object type')
        allowed = {'gid', 'name', 'lastUpdateTime', 'parentGID', 'type', 'comment',
                   'nodeGID', 'isProperty', 'subType', 'isGroup', 'refGIDs',
                   'ipv4Data', 'ipData', 'fqdnData', 'serviceParameters'}
        if any(child.tag not in allowed and (len(child) or (child.text or '').strip()) for child in obj):
            raise ValidationError('Unreviewed CSM object field')
        values = set()
        for ref in obj.findall('./refGIDs/gid'):
            values.update(self.resolve(required(ref, '.'), kind, stack + (gid,)))
        if kind == 'network':
            if obj.find('fqdnData') is not None:
                raise ValidationError('FQDN requires runtime resolution')
            literals = [n.text for key in ('ipv4Data', 'ipData') for n in obj.findall(key)]
            values.update(networks(literals))
        else:
            for param in obj.findall('serviceParameters'):
                values.update(self.parameter(param, stack + (gid,)))
        if not values:
            raise ValidationError('Empty or unsupported CSM object')
        record_object(self.referenced_objects, self.object_issues,
                      obj.findtext('name'), kind, values)
        return frozenset(values)

    def port_list(self, gid, stack=()):
        if gid in stack:
            raise ValidationError('Cyclic CSM port list')
        obj = self.object(gid)
        if obj.tag != 'portListPolicyObject':
            raise ValidationError('Expected CSM port list')
        result = []
        for ref in obj.findall('./refGIDs/gid'):
            result.extend(self.port_list(required(ref, '.'), stack + (gid,)))
        starts, ends = obj.findall('startPort'), obj.findall('endPort')
        if len(starts) != len(ends):
            raise ValidationError('Incomplete CSM port range')
        for a, b in zip(starts, ends):
            result.append(required(a, 'portNum') + '-' + required(b, 'portNum'))
        if not result:
            raise ValidationError('Empty CSM port list')
        record_object(self.referenced_objects, self.object_issues,
                      obj.findtext('name'), 'port_list', result)
        return result

    def parameter(self, param, stack=()):
        protocol = required(param, 'protocol')
        if any(child.tag not in ('protocol', 'destinationPort', 'sourcePort', 'icmpMessage') for child in param):
            raise ValidationError('Unreviewed CSM service field')
        if len(param.findall('destinationPort')) > 1:
            raise ValidationError('Repeated CSM destination port')
        dest = param.find('destinationPort')
        if dest is None:
            return service(protocol)
        if len(dest) != 1 or dest[0].tag not in ('port', 'portRefGID', 'portRef'):
            raise ValidationError('Invalid CSM destination port choice')
        # An explicitly empty port is malformed, not an omitted Any constraint.
        direct = required(dest, 'port') if dest[0].tag == 'port' else None
        ref = required(dest, dest[0].tag) if direct is None else None
        if (direct is None) == (ref is None):
            raise ValidationError('Invalid CSM destination port')
        return set().union(*(service(protocol, port) for port in
                               ([direct] if direct is not None else self.port_list(ref, stack))))

    def getPolicy(self, name):
        fields = {'name': name, 'policyType': 'DeviceAccessRuleFirewallPolicy'}
        combined = ET.Element('policyConfigDeviceResponse')
        rows, total, index, seen = 0, None, 0, set()
        self.cache.clear()
        while True:
            root = self.query('getPolicyConfigByName', 'policyConfigByNameRequest', fields)
            if root.tag != 'policyConfigDeviceResponse' or len(root.findall('policy')) != 1:
                raise ValidationError('Invalid CSM policy response')
            if root.find('overrideDetails') is not None:
                raise ValidationError('CSM device overrides require explicit resolution')
            for obj in root.findall('./policyObject/*'):
                gid = required(obj, 'gid')
                if gid in self.cache and ET.tostring(obj) != ET.tostring(self.cache[gid]):
                    raise ValidationError('CSM object changed during pagination')
                self.cache[gid] = obj
            rules = root.findall('./policy/deviceAccessRuleFirewallPolicy')
            if any(child.tag != 'deviceAccessRuleFirewallPolicy' for child in root.find('policy')):
                raise ValidationError('Unreviewed CSM policy row')
            for rule in rules:
                ident = required(rule, 'orderId')
                if ident in seen:
                    raise ValidationError('Repeated CSM rule')
                seen.add(ident)
                combined.append(rule)
            rows += len(rules)
            end, count = root.findtext('endIndex'), root.findtext('totalCount')
            if end is None and count is None:
                if total is not None and rows != total:
                    raise ValidationError('Incomplete CSM pagination')
                return ET.tostring(combined, encoding='unicode')
            try:
                end, count = int(required(root, 'endIndex')), int(required(root, 'totalCount'))
            except (ValueError, TypeError):
                raise ValidationError('Invalid CSM pagination metadata') from None
            if end <= index or end != rows or count < end or (total is not None and count != total):
                raise ValidationError('Inconsistent CSM pagination')
            total, index = count, end
            fields['startIndex'] = end
            if rows == total:
                return ET.tostring(combined, encoding='unicode')

    def PolicyRules(self, policy):
        root = parse_xml(policy)
        if root.tag != 'policyConfigDeviceResponse':
            raise ValidationError('Invalid CSM policy snapshot')
        if root.find('overrideDetails') is not None:
            raise ValidationError('CSM device overrides require explicit resolution')
        if root.find('endIndex') is not None or root.find('totalCount') is not None:
            raise ValidationError('Parse the complete CSM policy, not an individual page')
        if len(root.findall('policy')) > 1:
            raise ValidationError('Repeated CSM policy container')
        for container in root.findall('policy'):
            if any(child.tag != 'deviceAccessRuleFirewallPolicy' for child in container):
                raise ValidationError('Unreviewed CSM policy row')
        seen_objects = set()
        for obj in root.findall('./policyObject/*'):
            gid = required(obj, 'gid')
            if gid in seen_objects:
                raise ValidationError('Repeated CSM object in policy snapshot')
            seen_objects.add(gid)
            self.cache[gid] = obj
        result = []
        rules = root.findall('./deviceAccessRuleFirewallPolicy') + root.findall('./policy/deviceAccessRuleFirewallPolicy')
        seen_rules = set()
        for raw in rules:
            rule_number = required(raw, 'orderId')
            if rule_number in seen_rules:
                raise ValidationError('Repeated CSM rule in policy snapshot')
            seen_rules.add(rule_number)
            objects, issues, service_objects = {}, [], []
            self.referenced_objects, self.object_issues = {}, []
            def field(name):
                container = raw.find(name)
                if container is None or len(raw.findall(name)) != 1:
                    raise ValidationError('Missing CSM network container')
                for child in container:
                    if child.tag not in ('networkObjectGIDs', 'ipv4Data', 'ipData', 'interfaceRoleObjectGIDs'):
                        raise ValidationError('Unsupported CSM network constraint')
                names = []
                for ref in container.findall('./networkObjectGIDs/gid'):
                    gid = required(ref, '.')
                    obj = self.object(gid)
                    label = required(obj, 'name')
                    if label.startswith('@'):
                        raise ValidationError('CSM object name uses a reserved internal prefix')
                    names.append(label)
                    try:
                        resolved = sorted(self.resolve(gid, 'network'))
                        if label in objects and objects[label] != resolved:
                            raise ValidationError('Conflicting CSM object names')
                        objects[label] = resolved
                    except (APIError, ValidationError):
                        self.object_issues.append('Referenced network object could not be resolved')
                for i, literal in enumerate(container.findall('ipv4Data') + container.findall('ipData')):
                    resolved = sorted(networks([literal.text]))
                    label = '@literal:' + ','.join(resolved)
                    names.append(label)
                    objects[label] = resolved
                if not names:
                    names = ['@any']
                    objects['@any'] = ['0.0.0.0/0', '::/0']
                return names
            # Action, enabled state, interfaces and users do not participate.
            permit, enabled = raw.findtext('permit'), raw.findtext('isEnabled')
            svc = set()
            container = raw.find('services')
            if container is None or len(raw.findall('services')) != 1:
                raise ValidationError('Missing CSM services')
            if any(child.tag not in ('serviceObjectGIDs', 'serviceParameters') for child in container):
                raise ValidationError('Unsupported CSM service constraint')
            for ref in container.findall('./serviceObjectGIDs/gid'):
                gid = required(ref, '.')
                service_objects.append(required(self.object(gid), 'name'))
                try:
                    svc.update(self.resolve(gid, 'service'))
                except (APIError, ValidationError):
                    issues.append('Destination service could not be resolved')
                    self.object_issues.append('Referenced service object could not be resolved')
            for param in container.findall('serviceParameters'):
                svc.update(self.parameter(param))
            if not svc:
                svc = service('ip')
            result.append(Rule(rule_number, field('sources'), field('destinations'),
                               sorted(svc), 'ALLOW' if permit == 'true' else 'DROP',
                               enabled == 'true', objects, issues,
                               list(self.referenced_objects.values()), service_objects,
                               self.object_issues))
        return result

    def policy_rules(self, name):
        return self.PolicyRules(self.getPolicy(name))
