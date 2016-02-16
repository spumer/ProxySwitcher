# encoding: utf-8

import os
import re
import gzip
import time
import json
import socket
import random
import datetime
import functools
import threading
import collections
import urllib.error
import urllib.request


class ProxyURLRefreshError(Exception):
    pass


class Proxies:
    def __init__(
        self,
        proxies=None,
        proxies_url=None,
        proxies_file=None,
        options=None,
    ):
        """
        @param proxies: список адресов прокси-серверов
        @param proxies_url: ссылка на список прокси-серверов
        @param proxies_file: путь до файла со списком прокси-серверов
        @param options: доп. параметры
        """

        if options is None:
            options = {}

        auto_refresh_period = options.get('auto_refresh_period')
        if auto_refresh_period:
            auto_refresh_period = datetime.timedelta(**auto_refresh_period)

        self._proxies = proxies
        self.proxies_url = proxies_url
        self.proxies_file = proxies_file

        self.slice = options.get('slice')
        self.force_type = options.get('type')
        self.auto_refresh_period = auto_refresh_period

        self._last_auto_refresh = None
        self._auto_refresh_lock = threading.Lock()

        self._load_lock = threading.Lock()

    @property
    def proxies(self):
        if self._proxies is None:
            with self._load_lock:
                # Вышли из состояния гонки, теперь можно удостовериться в реальной необходимости
                if self._proxies is None:
                    self._proxies = self._load()

        return self._proxies

    def _load(self):
        if self.proxies_url:
            proxies = self.read_url(self.proxies_url)
        elif self.proxies_file:
            proxies = self.read_file(self.proxies_file)
        else:
            raise NotImplementedError(
                "Can't load proxies: "
                "please specify one of the sources ('proxies_url' or 'proxies_file')"
            )

        if self.slice:
            proxies = proxies[slice(*self.slice)]

        if self.force_type:
            new_type = self.force_type + '://'  # `socks` format
            proxies = tuple(
                re.sub(r'^(?:(.*?)://)?', new_type, proxy)
                for proxy in proxies
            )

        return proxies

    @classmethod
    def read_string(cls, string, sep=','):
        return tuple(x for x in map(str.strip, string.split(sep)) if x)

    @classmethod
    def read_url(cls, url, sep='\n', retry=10, sleep_range=(2, 10), timeout=2):
        while True:
            try:
                resp = urllib.request.urlopen(url, timeout=timeout)
                break
            except (urllib.error.HTTPError, socket.timeout):
                if not retry:
                    raise

                retry -= 1
                time.sleep(random.randint(*sleep_range))

        content = resp.read()

        if resp.headers.get('Content-Encoding', 'identity') == 'gzip':
            content = gzip.decompress(content)

        charset = resp.headers.get_content_charset('utf-8')
        content = content.decode(charset)

        return cls.read_string(content, sep=sep)

    @classmethod
    def read_file(cls, file_name, sep='\n'):
        with open(file_name) as f:
            return cls.read_string(f.read(), sep=sep)

    def refresh(self):
        if not self.proxies_url and not self.proxies_file:
            return

        try:
            self._proxies = self._load()
        except urllib.error.HTTPError:
            import problems
            problems.handle(ProxyURLRefreshError, extra={'url': self.proxies_url})
            return

    def _auto_refresh(self):
        if self.proxies_file:
            with self._auto_refresh_lock:
                modification_time = datetime.datetime.fromtimestamp(os.stat(self.proxies_file).st_mtime)

                if modification_time == self._last_auto_refresh:
                    return

                self.refresh()
                self._last_auto_refresh = modification_time
        elif self.proxies_url:
            if self.auto_refresh_period is None:
                return

            with self._auto_refresh_lock:
                now = datetime.datetime.now()

                if self._last_auto_refresh is not None:
                    if now - self._last_auto_refresh < self.auto_refresh_period:
                        return

                self.refresh()
                self._last_auto_refresh = now

    def get_random_address(self):
        self._auto_refresh()
        return random.choice(self.proxies)

    @classmethod
    def from_cfg_string(cls, cfg_string):
        """Возвращает список прокси как и `from_src`,
        с тем исключением что список опций берется автоматически.

        Формат: json

        Доступные опции:
            type ('socks5', 'http'; для полного списка типов см. модуль socks):
            все прокси будут автоматически промаркированы этип типом

            slice (tuple c аргументами для builtins.slice):
            будет взят только указанный фрагмент списка прокси-серверов

            auto_refresh_period (dict): {'days': ..., 'hours': ..., 'minutes': ...}
            как часто необходимо обновлять список прокси-серверов (только для `url` и `file`)

            (url, file, list) - может быть именем файла, ссылкой или списком в формате json

            Параметры slice и force_type являются необязательными

        Примеры:
            option = {"list": ["127.0.0.1:3128"]}
            option = {"list": ["127.0.0.1:3128", "127.0.0.1:9999"]}
            option = {"file": "./my_new_proxies.txt", "type": "socks5"}
            option = {"url": "http://example.com/get/proxy_list/", "slice": [35, null], "type": "http"}
            option = {"url": "http://example.com/get/proxy_list/", "auto_refresh_period": {"days": 1}}
        """

        cfg = json.loads(cfg_string)

        proxies = cfg.pop('list', None)
        proxies_url = cfg.pop('url', None)
        proxies_file = cfg.pop('file', None)

        return cls(
            proxies=proxies, proxies_url=proxies_url, proxies_file=proxies_file, options=cfg
        )


class Chain:
    """
    Не является потокобезопасным.
    """

    def __init__(self, proxies, proxy_gw=None):
        """
        @param proxies: список адресов прокси-серверов
        @param proxy_gw: прокси-сервер, который должен стоять во главе цепочки
         (все запросы к другим прокси-серверам будут проходить через него)
        """

        if isinstance(proxies, collections.Sequence):
            proxies = Proxies(proxies)

        self.proxies = proxies
        self.proxy_gw = proxy_gw

        self._path = []
        self.switch()

    def switch(self):
        self._path.clear()

        if self.proxy_gw:
            self._path.append(self.proxy_gw)

        self._path.append(self.proxies.get_random_address())

    def get_adapter(self):
        import socks.adapters
        return socks.adapters.ChainedProxyHTTPAdapter(chain=self._path)

    def get_handler(self):
        import socks.handlers
        return socks.handlers.ChainProxyHandler(chain=self._path)

    def wrap_session(self, session):
        adapter = self.get_adapter()
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        return session

    def wrap_module(self, module):
        """
        Attempts to replace a module's socket library with a SOCKS socket.
        This will only work on modules that import socket directly into the
        namespace; most of the Python Standard Library falls into this category.
        """
        import socks
        routes = socks.RoutingTable.from_addresses(self._path)
        module.socket.socket = functools.partial(socks.socksocket, routes=routes)

    @classmethod
    def from_config(cls, cfg):
        proxy_cfg_string = cfg.get('Прокси')

        if proxy_cfg_string is None:
            return None

        proxy_gw = cfg.get('Шлюз')
        proxies = Proxies.from_cfg_string(proxy_cfg_string)

        return cls(proxies, proxy_gw=proxy_gw)


class _RequestsClient:
    def __init__(self, proxy_chain=None, default_headers=None):
        default_headers_ = self._make_default_headers()
        if default_headers is not None:
            default_headers_.update(default_headers)

        self.proxy_chain = proxy_chain
        self.default_headers = default_headers_

        self.session = self._new_sess()

    def _make_default_headers(self):
        return {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0',
        }

    def _new_sess(self):
        import requests

        session = requests.Session()
        if self.default_headers is not None:
            session.headers.update(self.default_headers)
        if self.proxy_chain:
            self.proxy_chain.wrap_session(session)

        return session

    def switch_session(self):
        if self.proxy_chain:
            self.proxy_chain.switch()

        old_session = self.session
        self.session = self._new_sess()
        old_session.close()


class Client(_RequestsClient):
    def __init__(
        self, ssl_verify=True, timeout=10, apparent_encoding=None,
        raise_for_conn_problem=True, **kw
    ):
        super().__init__(**kw)

        self.ssl_verify = ssl_verify
        self.timeout = timeout
        self.apparent_encoding = apparent_encoding
        self.raise_for_conn_problem = raise_for_conn_problem

    def _setdefault_resp_encoding(self, resp):
        if resp.encoding is None:
            resp.encoding = self.apparent_encoding

    def _update_params_defaults(self, params):
        params.setdefault('timeout', self.timeout)
        params.setdefault('verify', self.ssl_verify)

    def request(self, method, url, **kw):
        from _УтилитыSbis import conn_problem_detector

        self._update_params_defaults(kw)

        with conn_problem_detector():
            resp = self.session.request(method, url, **kw)
            if self.raise_for_conn_problem:
                resp.raise_for_status()

        self._setdefault_resp_encoding(resp)
        return resp

    def get(self, url, **kw):
        return self.request('GET', url, **kw)

    def post(self, url, **kw):
        return self.request('POST', url, **kw)
