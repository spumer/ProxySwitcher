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
import collections.abc


class ProxyURLRefreshError(Exception):
    pass


class AliveProxiesNotFound(Exception):
    pass


class NoFreeProxies(Exception):
    pass


def _get_missing(target, source):
    """Возвращает присутствующие в `target`, но отсутствующие в `source` элементы
    """

    old_target = set(target)
    new_target = old_target.intersection(source)

    return old_target.difference(new_target)


class Proxies(collections.abc.Sequence):
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

        if proxies is not None:
            proxies = list(proxies)

        if options is None:
            options = {}

        auto_refresh_period = options.get('auto_refresh_period')
        if auto_refresh_period:
            auto_refresh_period = datetime.timedelta(**auto_refresh_period)

        blacklist_filename = options.get('blacklist')
        if blacklist_filename:
            blacklist = Blacklist.from_file(filename=blacklist_filename, missing_ok=True, auto_save=True)
        else:
            blacklist = Blacklist()

        self._proxies = proxies
        self.proxies_url = proxies_url
        self.proxies_file = proxies_file

        self.slice = options.get('slice')
        self.force_type = options.get('type')
        self.auto_refresh_period = auto_refresh_period

        self._blacklist = blacklist

        self._last_auto_refresh = None
        self._auto_refresh_lock = threading.Lock()

        self._load_lock = threading.Lock()
        self._modified_at = time.perf_counter()

        self._pool = _Pool(self)

    @property
    def proxies(self):
        if self._proxies is None:
            with self._load_lock:
                # Вышли из состояния гонки, теперь можно удостовериться в реальной необходимости
                if self._proxies is None:
                    self._proxies = self._load()
                    self._modified_at = time.perf_counter()

        return self._proxies

    def __getitem__(self, item):
        self._auto_refresh()
        return self.proxies[item]

    def __len__(self):
        self._auto_refresh()
        return len(self.proxies)

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
            proxies = [
                re.sub(r'^(?:(.*?)://)?', new_type, proxy)
                for proxy in proxies
            ]

        if self._blacklist:
            for proxy in _get_missing(self._blacklist, proxies):
                self._blacklist.discard(proxy)

            proxies = [p for p in proxies if p not in self._blacklist]

        return proxies

    @classmethod
    def read_string(cls, string, sep=','):
        return list(x for x in map(str.strip, string.split(sep)) if x)

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
        else:
            self._modified_at = time.perf_counter()

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

    def add_to_blacklist(self, proxy):
        with self._load_lock:
            if proxy in self.proxies:
                self._blacklist.append(proxy)
                self.proxies.remove(proxy)
                self._modified_at = time.perf_counter()

    def remove_from_blacklist(self, proxy):
        with self._load_lock:
            if proxy in self._blacklist:
                self._blacklist.discard(proxy)
                self.proxies.append(proxy)
                self._modified_at = time.perf_counter()

    def get_random_address(self):
        self._auto_refresh()
        proxies = self.proxies

        if not proxies:
            # Все прокси забанены, возвращаем самый старый из блеклиста. Возможно бан снят.
            # Мы не можем убрать его из блеклиста, тк он станет единственным доступным адресом
            # Что может вызвать проблемы при многопоточной работе
            # (возможен мгновенный повторный бан, если адрес получат все потоки)
            proxy = self._blacklist.popleft()
            self._blacklist.append(proxy)
            return proxy

        return random.choice(proxies)

    def get_pool(self):
        return self._pool

    @classmethod
    def from_cfg_string(cls, cfg_string):
        """Возвращает список прокси с тем исключением что список опций берется автоматически.

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


class _Pool:
    def __init__(self, proxies: "`Proxies` instance"):
        self._used = set()
        self._cooling_down = {}
        self._cond = threading.Condition()

        # более оптимальный способ заполнения, используется только для инициализации
        self._free = collections.deque(proxies.proxies)

        self._proxies = proxies
        self._proxies_modified_at = proxies._modified_at

    @property
    def _size(self):
        return len(self._free) + len(self._used) + len(self._cooling_down)

    def _cool_released(self):
        now = time.perf_counter()

        cooled = []

        for proxy, holdout in self._cooling_down.items():
            if now >= holdout:
                cooled.append(proxy)

        for proxy in cooled:
            self._cooling_down.pop(proxy)
            self._free.append(proxy)

    def _is_proxies_changed(self):
        return self._proxies._modified_at != self._proxies_modified_at

    def _remove_outdated(self):
        # список прокси изменился, оставляем только актуальные

        proxies = set(self._proxies)

        old_free = set(self._free)
        new_free = old_free.intersection(proxies)

        if old_free.difference(new_free):
            self._free.clear()
            self._free.extend(new_free)

        for proxy in _get_missing(self._cooling_down, proxies):
            self._cooling_down.pop(proxy)

        for proxy in _get_missing(self._used, proxies):
            self._used.remove(proxy)

    def acquire(self, timeout=None):
        start = time.perf_counter()

        with self._cond:
            while True:
                if self._is_proxies_changed():
                    self._remove_outdated()

                self._cool_released()

                if self._free:
                    proxy = self._free.popleft()
                    self._used.add(proxy)
                    return proxy

                if self._proxies._blacklist:
                    # Возвращаем самый старый из блеклиста. Возможно бан снят.
                    # Не убираем из блеклиста, чтобы не нарушать консистентности объекта self._proxies

                    proxy = next((
                        p for p in self._proxies._blacklist
                        if p not in self._cooling_down
                    ), None)

                    if proxy is not None:
                        self._proxies.remove_from_blacklist(proxy)
                        self._used.add(proxy)
                        return proxy
                    else:
                        # Все прокси из блеклиста находятся на охлаждении
                        pass

                if self._cooling_down:
                    self._cond.wait(1)
                else:
                    self._cond.wait(timeout)

                if timeout is not None:
                    if time.perf_counter() - start > timeout:
                        raise NoFreeProxies

    def release(self, proxy, bad=False, holdout=None):
        """Возвращает прокси в пул

        @param proxy: прокси
        @param holdout (сек): None - вернуть сразу, иначе прокси не будет использован до истечения указанного интервала
        """
        with self._cond:
            is_outdated = proxy not in self._used
            self._used.discard(proxy)

            if is_outdated:
                # Скорее всего прокси уже не актуален
                # И был удален из списка
                return

            if bad:
                self._proxies.add_to_blacklist(proxy)
                self._cond.notify()
                return

            if holdout is None:
                self._free.append(proxy)
                self._cond.notify()
            else:
                self._cooling_down[proxy] = time.perf_counter() + holdout


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

        if not isinstance(proxies, Proxies) and isinstance(proxies, collections.Sequence):
            proxies = Proxies(proxies)

        self.proxies = proxies
        self.proxy_gw = proxy_gw

        self._proxies_pool = self.proxies.get_pool()
        self._path = self._build_path(self._proxies_pool.acquire())

    def __del__(self):
        self._proxies_pool.release(self._path[-1])

    def _build_path(self, proxy):
        path = []

        if self.proxy_gw:
            path.append(self.proxy_gw)

        path.append(proxy)

        return path

    def switch(self, bad=False, holdout=None):
        self._proxies_pool.release(self._path[-1], bad=bad, holdout=holdout)
        self._path = self._build_path(self._proxies_pool.acquire())

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


class Blacklist(
    collections.abc.Container,
    collections.abc.Iterable,
    collections.abc.Sized,
):
    _missing = object()

    def __init__(self, sequence=None, filename=None, auto_save=False):
        self._filename = filename
        self._auto_save = auto_save

        self._blacklist = collections.OrderedDict.fromkeys(sequence or ())
        self._access_lock = threading.RLock()

    def __contains__(self, item):
        return item in self._blacklist

    def __iter__(self):
        return iter(self._blacklist)

    def __reversed__(self):
        return reversed(self._blacklist)

    def __len__(self):
        return len(self._blacklist)

    def __bool__(self):
        return len(self) != 0

    def _do_auto_save(self):
        if not self._auto_save:
            return

        if self._filename is None:
            raise RuntimeError("You must specify filename for autosave feature!")

        self.save(self._filename)

    def clear(self):
        self._blacklist.clear()
        self._do_auto_save()

    def append(self, value):
        """Добавляет элемент в конец списка
        Если он уже есть в нем, то переносит в конец
        """

        with self._access_lock:
            if value in self._blacklist:
                self._blacklist.move_to_end(value)
            else:
                self._blacklist[value] = None

            self._do_auto_save()

    def discard(self, value):
        with self._access_lock:
            self._blacklist.pop(value, None)
            self._do_auto_save()

    def pop(self):
        with self._access_lock:
            k, v = self._blacklist.popitem()
            self._do_auto_save()
            return k

    def popleft(self):
        with self._access_lock:
            k, v = self._blacklist.popitem(last=False)
            self._do_auto_save()
            return k

    def save(self, filename):
        os.makedirs(os.path.dirname(filename), exist_ok=True)

        with self._access_lock:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write('\n'.join(self._blacklist))

    def read(self, filename, missing_ok=False):
        try:
            with self._access_lock:
                with open(filename, encoding='utf-8') as f:
                    self._blacklist = collections.OrderedDict.fromkeys(x.strip() for x in f)
        except FileNotFoundError:
            if not missing_ok:
                raise

    @classmethod
    def from_file(cls, filename, missing_ok=False, **kw):
        obj = cls(filename=filename, **kw)
        obj.read(filename, missing_ok=missing_ok)
        return obj
