"""CSM 4.25 NBI reader; no import-time authentication or requests."""
import xml.etree.ElementTree as ET
from transport import Transport
from errors import APIError, ValidationError
from normalization import networks, service
from rule import Rule


def parse_xml(text):
    if '<!DOCTYPE' in text.upper() or '<!ENTITY' in text.upper():
        raise ValidationError('XML entities are not supported')
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        raise ValidationError('Invalid CSM XML') from None
    for node in root.iter():
        node.tag = node.tag.rsplit('}', 1)[-1]
    if root.find('.//error') is not None:
        raise APIError('CSM returned an application error')
    return root


def required(node, path):
    value = node.findtext(path)
    if value is None or not value.strip():
        raise ValidationError('Missing CSM field: ' + path)
    return value.strip()


class CSMClient(Transport):
    def __init__(self, base_url, **kwargs):
        super().__init__(base_url, **kwargs)
        self.cookie, self.cache = None, {}

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
        return result

    def parameter(self, param, stack=()):
        if param.find('sourcePort') is not None or (param.findtext('icmpMessage') or '').strip():
            raise ValidationError('Unsupported CSM source port or ICMP constraint')
        protocol = required(param, 'protocol')
        dest = param.find('destinationPort')
        if dest is None:
            return service(protocol)
        direct = dest.findtext('port')
        ref = dest.findtext('portRefGID') or dest.findtext('portRef')
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
            if root.tag != 'policyConfigDeviceResponse' or root.find('policy') is None:
                raise ValidationError('Invalid CSM policy response')
            if root.find('overrideDetails') is not None:
                raise ValidationError('CSM device overrides require explicit resolution')
            for obj in root.findall('./policyObject/*'):
                gid = required(obj, 'gid')
                if gid in self.cache and ET.tostring(obj) != ET.tostring(self.cache[gid]):
                    raise ValidationError('CSM object changed during pagination')
                self.cache[gid] = obj
            rules = root.findall('./policy/deviceAccessRuleFirewallPolicy')
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
                end, count = int(end), int(count)
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
        if root.find('endIndex') is not None or root.find('totalCount') is not None:
            raise ValidationError('Parse the complete CSM policy, not an individual page')
        for obj in root.findall('./policyObject/*'):
            self.cache[required(obj, 'gid')] = obj
        result = []
        rules = root.findall('./deviceAccessRuleFirewallPolicy') + root.findall('./policy/deviceAccessRuleFirewallPolicy')
        for raw in rules:
            objects, issues = {}, []
            def field(name):
                container = raw.find(name)
                if container is None:
                    raise ValidationError('Missing CSM network container')
                for child in container:
                    if child.tag not in ('networkObjectGIDs', 'ipv4Data', 'ipData', 'interfaceRoleObjectGIDs'):
                        raise ValidationError('Unsupported CSM network constraint')
                names = []
                for ref in container.findall('./networkObjectGIDs/gid'):
                    gid = required(ref, '.')
                    obj = self.object(gid)
                    label = required(obj, 'name')
                    names.append(label)
                    resolved = sorted(self.resolve(gid, 'network'))
                    if label in objects and objects[label] != resolved:
                        raise ValidationError('Conflicting CSM object names')
                    objects[label] = resolved
                for i, literal in enumerate(container.findall('ipv4Data') + container.findall('ipData')):
                    label = f'@{name}:{i}'
                    names.append(label)
                    objects[label] = sorted(networks([literal.text]))
                if not names:
                    names = ['@any']
                    objects['@any'] = ['0.0.0.0/0', '::/0']
                return names
            for key in ('interfaceRoleObjectGIDs', 'users', 'timeRangeObjectId', 'timeRangeObjectGID', 'securityGroups'):
                node = raw.find(key)
                if node is not None and (len(node) or (node.text or '').strip()):
                    issues.append('Unsupported CSM constraint: ' + key)
            for path in ('sources/interfaceRoleObjectGIDs/gid', 'destinations/interfaceRoleObjectGIDs/gid'):
                if raw.find(path) is not None:
                    issues.append('Unsupported CSM interface constraint')
            if raw.findtext('iosOptions', 'none').lower() != 'none':
                issues.append('Unsupported CSM IOS option')
            supported = {'gid', 'name', 'lastUpdateTime', 'updatedByUser', 'lastCommitTime',
                         'activityName', 'type', 'orderId', 'isMandatoryAggregation',
                         'configState', 'isEnabled', 'direction', 'permit', 'sources',
                         'destinations', 'services', 'logOptions', 'iosOptions', 'comment',
                         'interfaceRoleObjectGIDs'}
            for child in raw:
                if child.tag not in supported and (len(child) or (child.text or '').strip()):
                    issues.append('Unreviewed CSM rule field: ' + child.tag)
            permit, enabled = required(raw, 'permit'), required(raw, 'isEnabled')
            if permit not in ('true', 'false') or enabled not in ('true', 'false'):
                raise ValidationError('Invalid CSM boolean')
            svc = set()
            container = raw.find('services')
            if container is None:
                raise ValidationError('Missing CSM services')
            if any(child.tag not in ('serviceObjectGIDs', 'serviceParameters') for child in container):
                raise ValidationError('Unsupported CSM service constraint')
            for ref in container.findall('./serviceObjectGIDs/gid'):
                svc.update(self.resolve(required(ref, '.'), 'service'))
            for param in container.findall('serviceParameters'):
                svc.update(self.parameter(param))
            if not svc:
                svc = service('ip')
            result.append(Rule(required(raw, 'orderId'), field('sources'), field('destinations'),
                               sorted(svc), 'ALLOW' if permit == 'true' else 'DROP',
                               enabled == 'true', objects, issues))
        return result

    def policy_rules(self, name):
        return self.PolicyRules(self.getPolicy(name))
