"""Explicit, read-only HTTP transport. No request is made at construction."""
import time
from urllib.parse import urlsplit
import requests
from errors import APIError


class Transport:
    def __init__(self, base_url, session=None, verify=True, timeout=30, sleep=time.sleep):
        parts = urlsplit(base_url)
        if parts.scheme != 'https' or not parts.netloc or parts.username or parts.password or parts.query or parts.fragment:
            raise ValueError('An HTTPS base URL without credentials is required')
        self.base_url = base_url.rstrip('/')
        self.session = session if session is not None else requests.Session()
        self.verify, self.timeout, self.sleep = verify, timeout, sleep

    def request(self, method, path, **kwargs):
        if not path.startswith('/') or path.startswith('//'):
            raise ValueError('Relative API path required')
        for attempt in range(5):
            try:
                response = self.session.request(method, self.base_url + path,
                    verify=self.verify, timeout=self.timeout, allow_redirects=False, **kwargs)
            except requests.RequestException:
                raise APIError('API transport failed') from None
            if response.status_code == 429 and attempt < 4:
                try:
                    delay = min(60, max(0, float(response.headers.get('Retry-After', 2))))
                except ValueError:
                    delay = 2
                self.sleep(delay)
                continue
            if not 200 <= response.status_code < 300:
                raise APIError(f'API returned HTTP {response.status_code}')
            return response
        raise APIError('API rate limit exhausted')
