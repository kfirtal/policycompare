"""FMC REST reader. Authentication must be invoked explicitly."""
import json
from urllib.parse import quote
from transport import Transport
from errors import APIError, ValidationError
from normalization import networks, service
from rule import Rule, record_object
from response_validation import object_array, identifier

ENDPOINTS = {'Host': 'hosts', 'Network': 'networks', 'Range': 'ranges',
             'NetworkGroup': 'networkgroups', 'ProtocolPortObject': 'protocolportobjects',
             'PortObjectGroup': 'portobjectgroups'}


class FMCClient(Transport):
    def __init__(self, base_url, domain=None, **kwargs):
        super().__init__(base_url, **kwargs)
        self.domain, self.token, self.cache = domain, None, {}
        self.raw_cache, self.referenced_objects, self.object_issues = {}, {}, []

    def login(self, username, password):
        self.token = None
        self.cache.clear()
        self.raw_cache.clear()
        response = self.request('POST', '/api/fmc_platform/v1/auth/generatetoken', auth=(username, password))
        try:
            token = response.headers['X-auth-access-token']
            domains = json.loads(response.headers['DOMAINS'])
            if not isinstance(domains, list) or any(not isinstance(d, dict) for d in domains):
                raise ValueError()
            for domain in domains:
                identifier(domain.get('uuid'))
            identifier(token)
            if self.domain is None:
                if len(domains) != 1:
                    raise ValueError()
                self.domain = domains[0]['uuid']
            if self.domain not in [d['uuid'] for d in domains] or not token:
                raise ValueError()
        except (KeyError, ValueError, TypeError):
            raise APIError('Invalid token or ambiguous FMC domain') from None
        self.token, self.cache = token, {}

    def close(self):
        """Discard the local token; the server token expires independently."""
        self.token = None
        self.cache.clear()
        self.raw_cache.clear()
        self.referenced_objects.clear()
        self.object_issues.clear()
        super().close()

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
            if 'offset' in paging and (type(paging['offset']) is not int or paging['offset'] != offset):
                raise ValidationError('Unexpected FMC page offset')
            for item in items:
                if not isinstance(item, dict):
                    raise ValidationError('Invalid FMC collection item')
                identifier(item.get('id'))
                if item['id'] in seen:
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
        if not isinstance(ref, dict):
            raise ValidationError('Invalid FMC object reference')
        typ, ident = ref.get('type'), ref.get('id')
        identifier(ident)
        key = (typ, ident, kind)
        allowed_types = {'network': {'Host', 'Network', 'Range', 'NetworkGroup'},
                         'service': {'ProtocolPortObject', 'PortObjectGroup'}}
        if not isinstance(typ, str) or typ not in allowed_types.get(kind, set()):
            raise ValidationError('Unsupported FMC object reference')
        if key in stack:
            raise ValidationError('Cyclic FMC object group')
        # Cache HTTP responses, but traverse each rule's groups again so that
        # its inventory includes all nested members even on a cache hit.
        if key not in self.raw_cache:
            self.raw_cache[key] = self.get('/object/' + ENDPOINTS[typ] + '/' + quote(ident, safe=''))
        obj = self.raw_cache[key]
        if obj.get('type') != typ or obj.get('id') != ident or obj.get('overrides') or obj.get('overridable'):
            raise ValidationError('Invalid FMC object or unresolved override')
        values = set()
        if typ in ('NetworkGroup', 'PortObjectGroup'):
            for member in object_array(obj, 'objects'):
                values.update(self.resolve(member, kind, stack + (key,)))
            if 'literals' in obj and 'literal' in obj:
                raise ValidationError('Ambiguous FMC literal arrays')
            literals = object_array(obj, 'literals' if 'literals' in obj else 'literal')
            for lit in literals:
                values.update(self.literal(lit, kind))
        else:
            values.update(self.literal(obj, kind))
        if not values:
            raise ValidationError('Empty FMC object')
        record_object(self.referenced_objects, self.object_issues,
                      obj.get('name', ref.get('name')), kind, values)
        self.cache[key] = frozenset(values)
        return self.cache[key]

    @staticmethod
    def literal(obj, kind):
        if not isinstance(obj, dict):
            raise ValidationError('Invalid FMC literal')
        if kind == 'network':
            if obj.get('type') not in ('Host', 'Network', 'Range') or 'value' not in obj:
                raise ValidationError('Unsupported FMC network literal')
            return networks([obj['value']])
        if obj.get('type') not in ('PortLiteral', 'ProtocolPortObject') or 'protocol' not in obj:
            raise ValidationError('Unsupported FMC service literal')
        if 'port' in obj and (obj['port'] is None or not str(obj['port']).strip()):
            raise ValidationError('Explicit FMC port value is empty')
        return service(obj['protocol'], obj.get('port'))

    def policy_rules(self, policy_uuid):
        identifier(policy_uuid)
        self.cache.clear()  # no stale object values across comparisons
        self.raw_cache.clear()
        result = []
        for index, raw in enumerate(self.collection('/policy/accesspolicies/' + quote(policy_uuid, safe='') + '/accessrules')):
            issues, objects, service_objects = [], {}, []
            self.referenced_objects, self.object_issues = {}, []
            def field(name, kind):
                container = raw.get(name, {})
                if not isinstance(container, dict) or container.keys() - {'objects', 'literals'}:
                    raise ValidationError('Unsupported FMC rule container')
                values, names = set(), []
                for ref in object_array(container, 'objects'):
                    label = ref.get('name')
                    identifier(label)
                    if label.startswith('@'):
                        raise ValidationError('FMC object name uses a reserved internal prefix')
                    names.append(label)
                    if kind == 'service':
                        service_objects.append(label)
                    try:
                        resolved = self.resolve(ref, kind)
                        if kind == 'network':
                            objects[label] = sorted(resolved)
                        values.update(resolved)
                    except (APIError, ValidationError):
                        self.object_issues.append('Referenced object could not be resolved')
                        if kind == 'service':
                            issues.append('Destination service could not be resolved')
                for i, lit in enumerate(object_array(container, 'literals')):
                    resolved = self.literal(lit, kind)
                    label = '@literal:' + ','.join(sorted(resolved)) if kind == 'network' else f'@{name}:{i}'
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
            # All fields outside the user's three comparison fields are ignored.
            src = field('sourceNetworks', 'network')
            dst = field('destinationNetworks', 'network')
            svc = field('destinationPorts', 'service')
            result.append(Rule(raw['id'], src, dst, svc,
                               'DROP' if raw.get('action') == 'BLOCK' else 'ALLOW',
                               raw.get('enabled'), objects, issues,
                               list(self.referenced_objects.values()), service_objects,
                               self.object_issues))
        return result
