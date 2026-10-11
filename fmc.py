"""FMC REST reader. Authentication must be invoked explicitly."""
import json
from urllib.parse import quote
from transport import Transport
from errors import APIError, ValidationError
from normalization import networks, service
from rule import Rule

ENDPOINTS = {'Host': 'hosts', 'Network': 'networks', 'Range': 'ranges',
             'NetworkGroup': 'networkgroups', 'ProtocolPortObject': 'protocolportobjects',
             'PortObjectGroup': 'portobjectgroups'}


class FMCClient(Transport):
    def __init__(self, base_url, domain=None, **kwargs):
        super().__init__(base_url, **kwargs)
        self.domain, self.token, self.cache = domain, None, {}

    def login(self, username, password):
        response = self.request('POST', '/api/fmc_platform/v1/auth/generatetoken', auth=(username, password))
        try:
            token = response.headers['X-auth-access-token']
            domains = json.loads(response.headers['DOMAINS'])
            if self.domain is None:
                if len(domains) != 1:
                    raise ValueError()
                self.domain = domains[0]['uuid']
            if self.domain not in [d['uuid'] for d in domains] or not token:
                raise ValueError()
        except (KeyError, ValueError, TypeError):
            raise APIError('Invalid token or ambiguous FMC domain') from None
        self.token, self.cache = token, {}

    def get(self, path, **kwargs):
        if not self.token or not self.domain:
            raise APIError('FMC login required')
        response = self.request('GET', '/api/fmc_config/v1/domain/' + quote(self.domain, safe='') + path,
                                headers={'X-auth-access-token': self.token}, **kwargs)
        try:
            data = response.json()
            if not isinstance(data, dict):
                raise ValueError()
            return data
        except ValueError:
            raise APIError('Invalid FMC JSON') from None

    def collection(self, path):
        offset, total, seen = 0, None, set()
        result = []
        while True:
            data = self.get(path, params={'offset': offset, 'limit': 1000, 'expanded': 'true'})
            items, paging = data.get('items'), data.get('paging', {})
            if not isinstance(items, list) or not isinstance(paging, dict):
                raise ValidationError('Invalid FMC collection')
            count = paging.get('count')
            if not isinstance(count, int) or isinstance(count, bool) or count < 0:
                raise ValidationError('Missing FMC total count')
            if total is not None and count != total:
                raise ValidationError('FMC collection changed during pagination')
            total = count
            for item in items:
                if not isinstance(item, dict) or not item.get('id') or item['id'] in seen:
                    raise ValidationError('Missing or repeated FMC item ID')
                seen.add(item['id'])
            result.extend(items)
            offset += len(items)
            if offset == total:
                return result
            if not items or offset > total:
                raise ValidationError('Incomplete FMC pagination')

    def policy_uuid_by_name(self, name):
        matches = [p['id'] for p in self.collection('/policy/accesspolicies') if p.get('name') == name]
        if len(matches) != 1:
            raise ValidationError('Policy name must match exactly one FMC policy')
        return matches[0]

    def resolve(self, ref, kind, stack=()):
        typ, ident = ref.get('type'), ref.get('id')
        key = (typ, ident, kind)
        if typ not in ENDPOINTS or not ident:
            raise ValidationError('Unsupported FMC object reference')
        if key in stack:
            raise ValidationError('Cyclic FMC object group')
        if key in self.cache:
            return self.cache[key]
        obj = self.get('/object/' + ENDPOINTS[typ] + '/' + quote(ident, safe=''))
        if obj.get('type') != typ or obj.get('id') != ident or obj.get('overrides') or obj.get('overridable'):
            raise ValidationError('Invalid FMC object or unresolved override')
        values = set()
        if typ in ('NetworkGroup', 'PortObjectGroup'):
            for member in obj.get('objects', []):
                values.update(self.resolve(member, kind, stack + (key,)))
            literals = obj.get('literals', obj.get('literal', []))
            for lit in literals:
                values.update(self.literal(lit, kind))
        else:
            values.update(self.literal(obj, kind))
        if not values:
            raise ValidationError('Empty FMC object')
        self.cache[key] = frozenset(values)
        return self.cache[key]

    @staticmethod
    def literal(obj, kind):
        if obj.get('sourcePort') or obj.get('sourcePorts'):
            raise ValidationError('Unsupported FMC source port constraint')
        if kind == 'network':
            if obj.get('type') not in ('Host', 'Network', 'Range') or 'value' not in obj:
                raise ValidationError('Unsupported FMC network literal')
            return networks([obj['value']])
        if obj.get('type') not in ('PortLiteral', 'ProtocolPortObject') or 'protocol' not in obj:
            raise ValidationError('Unsupported FMC service literal')
        return service(obj['protocol'], obj.get('port'))

    def policy_rules(self, policy_uuid):
        self.cache.clear()  # no stale object values across comparisons
        result = []
        for index, raw in enumerate(self.collection('/policy/accesspolicies/' + quote(policy_uuid, safe='') + '/accessrules')):
            issues, objects = [], {}
            def field(name, kind):
                container = raw.get(name, {})
                if not isinstance(container, dict) or container.keys() - {'objects', 'literals'}:
                    raise ValidationError('Unsupported FMC rule container')
                values, names = set(), []
                for ref in container.get('objects', []):
                    resolved = self.resolve(ref, kind)
                    label = ref.get('name', ref['id'])
                    names.append(label)
                    if kind == 'network':
                        if label in objects and objects[label] != sorted(resolved):
                            raise ValidationError('Conflicting FMC object names')
                        objects[label] = sorted(resolved)
                    values.update(resolved)
                for i, lit in enumerate(container.get('literals', [])):
                    resolved = self.literal(lit, kind)
                    label = f'@{name}:{i}'
                    names.append(label)
                    if kind == 'network':
                        objects[label] = sorted(resolved)
                    values.update(resolved)
                if not names:
                    if kind == 'network':
                        names = ['@any']
                        objects['@any'] = ['0.0.0.0/0', '::/0']
                    else:
                        values = service('ip')
                return names if kind == 'network' else sorted(values)
            for key in ('sourcePorts', 'sourceZones', 'destinationZones', 'users', 'applications', 'urls', 'vlanTags', 'sourceSecurityGroupTags', 'destinationSecurityGroupTags', 'timeRange', 'sourceDynamicObjects', 'destinationDynamicObjects'):
                if raw.get(key):
                    issues.append('Unsupported FMC constraint: ' + key)
            supported = {'id', 'name', 'type', 'links', 'metadata', 'action', 'enabled',
                         'sourceNetworks', 'destinationNetworks', 'destinationPorts',
                         'sendEventsToFMC', 'logBegin', 'logEnd', 'logFiles', 'enableSyslog',
                         'syslogConfig', 'variableSet', 'ruleIndex', 'category', 'section'}
            for key in raw.keys() - supported:
                if raw[key]:
                    issues.append('Unreviewed FMC rule field: ' + key)
            if raw.get('action') not in ('ALLOW', 'BLOCK'):
                issues.append('Unsupported FMC action')
            if not isinstance(raw.get('enabled'), bool):
                issues.append('Missing FMC enabled state')
            src = field('sourceNetworks', 'network')
            dst = field('destinationNetworks', 'network')
            svc = field('destinationPorts', 'service')
            result.append(Rule(raw['id'], src, dst, svc,
                               'DROP' if raw.get('action') == 'BLOCK' else 'ALLOW',
                               raw.get('enabled'), objects, issues))
        return result

