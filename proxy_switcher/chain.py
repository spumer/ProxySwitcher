# encoding: utf-8

import os
import re
import sys
import gzip
import time
import json
import socket
import random
import weakref
import datetime
import functools
import threading
import collections
import urllib.error
import urllib.request
import collections.abc

import json_dict

from . import utils


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

        shuffle = options.get('shuffle', False)

        if proxies is not None:
            proxies = list(proxies)
            if shuffle:
                random.shuffle(proxies)

        auto_refresh_period = options.get('auto_refresh_period')
        if auto_refresh_period:
            auto_refresh_period = datetime.timedelta(**auto_refresh_period)

        blacklist = utils.get_json_dict(json_dict.JsonLastUpdatedOrderedDict, filename=options.get('blacklist'))
        cooling_down = utils.get_json_dict(json_dict.JsonOrderedDict, filename=options.get('cooldown'))
        stats = utils.get_json_dict(json_dict.JsonDict, filename=options.get('stats'))

        self._proxies = proxies
        self.proxies_url = proxies_url
        self.proxies_file = proxies_file

        self._shuffle = shuffle
        self.slice = options.get('slice')
        self.force_type = options.get('type')
        self.auto_refresh_period = auto_refresh_period

        self._blacklist = blacklist
        self._cooling_down = cooling_down
        self._stats = stats
        self._cleanup_lock = threading.RLock()

        self._last_auto_refresh = None
        self._auto_refresh_lock = threading.Lock()

        self._load_lock = threading.Lock()
        self._modified_at = time.perf_counter()

        self.__pool = None
        self._smart_holdout_start = options.get('smart_holdout_start')

        self._options = options

        if self._proxies is not None:
            proxies = set(self._proxies)
            self._cleanup_internals(proxies)

    @property
    def proxies(self):
        if self._proxies is None:
            with self._load_lock:
                # Вышли из состояния гонки, теперь можно удостовериться в реальной необходимости
                if self._proxies is None:
                    self._proxies = self._load()
                    self._cleanup_internals(self._proxies)
                    self._modified_at = time.perf_counter()

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
            proxies = [
                re.sub(r'^(?:(.*?)://)?', new_type, proxy)
                for proxy in proxies
            ]

        if self._shuffle:
            random.shuffle(proxies)

        return proxies

    def _cleanup_internals(self, proxies):
        with self._cleanup_lock:
            self._cleanup_blacklist(proxies)
            self._cleanup_cooling_down(proxies)
            self._cleanup_stats(proxies)

    def _cleanup_cooling_down(self, proxies):
        for proxy in _get_missing(self._cooling_down, proxies):
            self._cooling_down.pop(proxy)

    def _cleanup_blacklist(self, proxies):
        for proxy in _get_missing(self._blacklist, proxies):
            self._blacklist.pop(proxy)

    def _cleanup_stats(self, proxies):
        for proxy in _get_missing(self._stats, proxies):
            self._stats.pop(proxy)

    def _get_options(self, *options, missing_ok=True):
        if missing_ok:
            return {k: self._options.get(k) for k in options}
        else:
            return {k: self._options[k] for k in options}

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
            self._cleanup_internals(self._proxies)
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

    def get_random_address(self):
        self._auto_refresh()
        return random.choice(self.proxies)

    def get_pool(self):
        if self.__pool is None:
            with self._cleanup_lock:  # оптимизация: используем уже существующий лок
                # Вышли из состояния гонки, теперь можно удостовериться в реальной необходимости
                if self.__pool is None:
                    options = self._get_options('default_holdout', 'default_bad_holdout', 'force_defaults')

                    if self._smart_holdout_start is not None:
                        options['smart_holdout'] = True
                        options['smart_holdout_start'] = self._smart_holdout_start
                        options.update(self._get_options('smart_holdout_min', 'smart_holdout_max'))

                    self.__pool = _Pool(
                        self, self._cooling_down, self._blacklist, self._stats, self._cleanup_lock,
                        **options
                    )

        return self.__pool

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
    def __init__(
            self, proxies: "`Proxies` instance", cooling_down, blacklist, stats, _cleanup_lock=None,
            smart_holdout=False, smart_holdout_start=None, smart_holdout_min=None, smart_holdout_max=None,
            default_holdout=None, default_bad_holdout=None, force_defaults=False,
    ):
        if smart_holdout:
            if smart_holdout_start in (None, 0):
                raise RuntimeError("Вы должны указать начальное время охлаждения")

            if smart_holdout_max is None:
                smart_holdout_max = float('inf')

        self._used = set()
        self._cond = threading.Condition(lock=_cleanup_lock)

        self._free = collections.deque(
            p for p in proxies.proxies
            if (
                p not in blacklist and
                p not in cooling_down
            )
        )

        self._proxies = proxies
        self._cooling_down = cooling_down
        self._blacklist = blacklist
        self._stats = stats

        self._smart_holdout = smart_holdout
        self._smart_holdout_start = smart_holdout_start
        self._smart_holdout_min = smart_holdout_min or 0
        self._smart_holdout_max = smart_holdout_max

        self._default_holdout = default_holdout
        self._default_bad_holdout = default_bad_holdout
        self._force_defaults = force_defaults

        self._proxies_modified_at = proxies._modified_at

    @property
    def _size(self):
        return len(self._free) + len(self._used) + len(self._cooling_down) + len(self._blacklist)

    def _cool_released(self):
        now = time.time()

        cooled = []

        for proxy, holdout in self._cooling_down.items():
            if now >= holdout:
                cooled.append(proxy)

        for proxy in cooled:
            self._cooling_down.pop(proxy, None)
            if proxy not in self._blacklist:
                self._free.append(proxy)

    def _is_proxies_changed(self):
        self._proxies._auto_refresh()
        return self._proxies._modified_at != self._proxies_modified_at

    def _remove_outdated(self):
        # список прокси изменился, оставляем только актуальные

        full_list = set(self._proxies.proxies)

        for proxy in _get_missing(self._blacklist, full_list):
            self._blacklist.pop(proxy, None)

        for proxy in _get_missing(self._cooling_down, full_list):
            self._cooling_down.pop(proxy, None)

        for proxy in _get_missing(self._used, full_list):
            self._used.remove(proxy)

        for proxy in _get_missing(self._stats, full_list):
            self._stats.pop(proxy, None)

        free = set(
            p for p in full_list
            if (
                p not in self._used and
                p not in self._blacklist and
                p not in self._cooling_down
            )
        )

        old_free = set(self._free)
        new_free = old_free.intersection(free)

        if old_free.difference(new_free):
            self._free.clear()
            self._free.extend(new_free)

        self._proxies_modified_at = self._proxies._modified_at

    def _update_stats(self, proxy, bad=False, holdout=None):
        proxy_stat = self._stats.get(proxy) or {}

        ok, fail = proxy_stat.get('uptime', (0, 0))

        if not bad:
            ok += 1
        else:
            fail += 1

        proxy_stat['uptime'] = ok, fail
        proxy_stat['last_holdout'] = holdout
        if (
            not bad or
            (
                holdout is not None and
                holdout >= (proxy_stat.get('last_good_holdout') or 0)
            )
        ):
            proxy_stat['last_good_holdout'] = holdout

        # универсальный способ сказать что статистика обновилась
        # тк без вызова метода .save будет работать и с обычным словарем (не только с JsonDict)
        self._stats[proxy] = proxy_stat

    def _get_next_holdout(self, proxy, bad=False):
        """Рассчитывает время охлаждения.

        @param proxy: прокси, для которого необходимо вычислить
        @param bad: True - вычисляем охлаждение для неудачи, иначе False
        @return: рекомендуемое время охлаждения в секундах или None, если недостаточно данных
        """

        # Алгоритм основан на бинарном поиске,
        # в отличии от которого нам не известна верхняя граница

        proxy_stat = self._stats.get(proxy)
        if proxy_stat is None:
            return None

        last_holdout = proxy_stat['last_holdout']
        last_good_holdout = proxy_stat.get('last_good_holdout', 0)

        lo = last_holdout  # предыдущее время охлаждения (нижняя граница)

        if bad:
            # Мы получили "бан" ...
            if lo < last_good_holdout:
                # ... возвращаемся к предыдущему хорошему значению ...
                holdout = last_good_holdout
            else:
                # ... или сдвигаем границу дальше
                holdout = lo * 2
        else:
            # возвращаемся к предыдущей границе (lo / 2)
            # но с небольшим отступом - на середину отрезка [(lo / 2), lo]
            holdout = lo * 0.75

        return holdout

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

                if self._blacklist:
                    # Возвращаем самый стабильный из блеклиста. Возможно бан снят.

                    def _uptime(p):
                        uptime = float('inf')

                        p_stat = self._stats.get(p)
                        if p_stat is not None:
                            ok, failed = p_stat.get('uptime', (0, 0))
                            if failed != 0:
                                uptime = ok // failed
                            else:
                                uptime = ok

                        return uptime

                    proxy = next((
                        p for p in sorted(self._blacklist, key=_uptime, reverse=True)
                        if p not in self._cooling_down
                    ), None)

                    if proxy is not None:
                        self._blacklist.pop(proxy)
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

    def release(self, proxy, bad=False, holdout=None, bad_reason=None):
        """Возвращает прокси в пул

        @param proxy: прокси
        @param holdout (сек): None - вернуть сразу, иначе прокси не будет использован до истечения указанного интервала
        """
        with self._cond:
            is_outdated = proxy not in self._used

            if is_outdated:
                # Скорее всего прокси уже не актуален
                # И был удален из списка
                return

            self._used.remove(proxy)

            if holdout is None or self._force_defaults:
                holdout = self._default_holdout if not bad else self._default_bad_holdout

            if self._smart_holdout:
                _holdout = (
                    self._get_next_holdout(proxy, bad=bad) or
                    holdout or
                    self._smart_holdout_start
                )

                # Не позволяем границе опуститься слишком низко
                if _holdout < self._smart_holdout_min:
                    holdout = self._smart_holdout_min
                elif _holdout > self._smart_holdout_max:
                    holdout = self._smart_holdout_max
                else:
                    holdout = max(self._smart_holdout_min, _holdout)

            if holdout is not None:
                self._cooling_down[proxy] = time.time() + holdout

            if bad:
                self._blacklist[proxy] = bad_reason
            elif holdout is None:
                # прокси не требует остывания
                self._free.append(proxy)
                self._cond.notify()

            self._update_stats(proxy, bad=bad, holdout=holdout)


class IChain:
    def switch(self, bad=False, holdout=None, bad_reason=None, lazy=False):
        raise NotImplementedError

    def get_adapter(self):
        raise NotImplementedError

    def get_handler(self):
        raise NotImplementedError

    def get_path(self):
        raise NotImplementedError

    def wrap_session(self, session):
        raise NotImplementedError

    def wrap_module(self, module, all_threads=False):
        """
        Attempts to replace a module's socket library with a SOCKS socket.
        This will only work on modules that import socket directly into the
        namespace; most of the Python Standard Library falls into this category.
        """
        import socks
        import socks.monkey_socket

        routes = socks.RoutingTable.from_addresses(self.get_path())

        if not all_threads:
            socks.monkey_socket.socks_wrap_module_thread(routes, module)
        else:
            socks.monkey_socket.socks_wrap_module_global(routes, module)


class Chain(IChain):
    """
    Не является потокобезопасным.
    """

    def __init__(self, proxies, proxy_gw=None, use_pool=False, pool_acquire_timeout=None):
        """
        @param proxies: список адресов прокси-серверов
        @param proxy_gw: прокси-сервер, который должен стоять во главе цепочки
         (все запросы к другим прокси-серверам будут проходить через него)
        @param use_pool: использовать список прокси в качестве пула
        @param pool_acquire_timeout (сек.): если за указанный период не удастся получить свободный прокси
         будет брошено исключение `NoFreeProxies`, None - ждать до появления свободного адреса
        """
        if not isinstance(proxies, Proxies) and isinstance(proxies, collections.Sequence):
            proxies = Proxies(proxies)

        if use_pool:
            pool = proxies.get_pool()
        else:
            pool = None

        self.proxies = proxies
        self.proxy_gw = proxy_gw

        self._proxies_pool = pool
        self._current_pool_proxy = None
        self._pool_acquire_timeout = pool_acquire_timeout

        self.__path = []

        if sys.version_info >= (3, 4, 0):
            self.finalizer = weakref.finalize(self, self.finalize)

    def __del__(self):
        if sys.version_info < (3, 4, 0):
            self.finalize()

    def finalize(self):
        if self._proxies_pool is not None:
            self._release_pool_proxy()

    def _build_path(self, proxy):
        path = []

        if self.proxy_gw:
            path.append(self.proxy_gw)

        path.append(proxy)

        return path

    def _release_pool_proxy(self, bad=False, holdout=None, bad_reason=None):
        if self._current_pool_proxy:
            proxy = self._current_pool_proxy

            self._current_pool_proxy = None
            self._proxies_pool.release(proxy, bad=bad, holdout=holdout, bad_reason=bad_reason)

    def _acquire_pool_proxy(self):
        proxy = self._proxies_pool.acquire(timeout=self._pool_acquire_timeout)
        self._current_pool_proxy = proxy
        return proxy

    def _get_proxy(self):
        if self._proxies_pool is not None:
            return self._acquire_pool_proxy()
        else:
            return self.proxies.get_random_address()

    @property
    def _path(self):
        if not self.__path:
            self.__path = self._build_path(self._get_proxy())
        return self.__path

    def get_path(self):
        return self._path

    def switch(self, bad=False, holdout=None, bad_reason=None, lazy=False):
        self.__path.clear()

        if self._proxies_pool is not None:
            self._release_pool_proxy(bad, holdout, bad_reason)

        if not lazy:
            self.__path = self._build_path(self._get_proxy())

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

    @classmethod
    def from_config(cls, cfg):
        proxy_cfg_string = cfg.get('Прокси')

        if proxy_cfg_string is None:
            return None

        proxy_gw = cfg.get('Шлюз')
        proxies = Proxies.from_cfg_string(proxy_cfg_string)

        return cls(proxies, proxy_gw=proxy_gw)


class MultiChain(IChain):
    def __init__(self, *proxies_all, use_pool=True, pool_acquire_timeout=None):
        if use_pool:
            pool_kw = {'use_pool': True, 'pool_acquire_timeout': 1}
        else:
            pool_kw = {}

        self._pool_acquire_timeout = pool_acquire_timeout

        self._chains = collections.deque(
           Chain(p, gw, **pool_kw)
           for p, gw in self._unwrap_proxies_all(proxies_all)
        )

    @staticmethod
    def _unwrap_proxies_all(proxies_all):
        for p in proxies_all:
            if isinstance(p, tuple):
                # (Proxies, Gateway)
                p, gw = p
            else:
                # Proxies
                p, gw = p, None

            yield p, gw

    def _self_auto_rotate(func):
        @functools.wraps(func)
        def wrapped(self, *args, **kw):
            start = time.perf_counter()
            while True:
                try:
                    return func(self, *args, **kw)
                except NoFreeProxies:
                    self._rotate()  # FIXME: cycle rotate is normal?
                    if (
                        self._pool_acquire_timeout is not None and
                        time.perf_counter() - start > self._pool_acquire_timeout
                    ):
                        raise
        return wrapped

    @property
    def _current(self):
        return self._chains[-1]

    def get_path(self):
        return self._current.get_path()

    def _rotate(self):
        self._chains.rotate(1)

    def switch(self, bad=False, holdout=None, bad_reason=None, lazy=False):
        self._current.switch(bad=bad, holdout=holdout, bad_reason=bad_reason, lazy=True)
        self._rotate()
        if not lazy:
            self._enforce_current_path_build()

    @_self_auto_rotate
    def _enforce_current_path_build(self):
        _ = self._current._path  # FIXME: ugly enforce path building after switching

    @_self_auto_rotate
    def get_adapter(self):
        return self._current.get_adapter()

    @_self_auto_rotate
    def get_handler(self):
        return self._current.get_handler()

    @_self_auto_rotate
    def wrap_session(self, session):
        return self._current.wrap_session(session)

    @_self_auto_rotate
    def wrap_module(self, module):
        return self._current.wrap_module(module)
