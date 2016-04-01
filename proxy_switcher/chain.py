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

import json_dict


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

        blacklist_filename = options.get('blacklist')
        if blacklist_filename:
            blacklist = json_dict.JsonLastUpdatedOrderedDict(filename=blacklist_filename, auto_save=True)
        else:
            blacklist = json_dict.LastUpdatedOrderedDict()

        cooldown_filename = options.get('cooldown')
        if cooldown_filename:
            cooling_down = json_dict.JsonOrderedDict(filename=cooldown_filename, auto_save=True)
        else:
            cooling_down = collections.OrderedDict()

        stats_filename = options.get('stats')
        if stats_filename:
            stats = json_dict.JsonDict(filename=stats_filename, auto_save=True)
        else:
            stats = {}

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
        self._smart_holdout_start = options.get('smart_holdout_start')
        self._smart_holdout_min = options.get('smart_holdout_min')

        self._last_auto_refresh = None
        self._auto_refresh_lock = threading.Lock()

        self._load_lock = threading.Lock()
        self._modified_at = time.perf_counter()

        self.__pool = None

        if self._proxies is not None:
            proxies = set(self._proxies)
            self._cleanup_blacklist(proxies)
            self._cleanup_cooling_down(proxies)
            self._cleanup_stats(proxies)

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

        self._cleanup_blacklist(proxies)
        self._cleanup_cooling_down(proxies)
        self._cleanup_stats(proxies)

        if self._shuffle:
            random.shuffle(proxies)

        return proxies

    def _cleanup_cooling_down(self, proxies):
        for proxy in _get_missing(self._cooling_down, proxies):
            self._cooling_down.pop(proxy)

    def _cleanup_blacklist(self, proxies):
        for proxy in _get_missing(self._blacklist, proxies):
            self._blacklist.pop(proxy)

    def _cleanup_stats(self, proxies):
        for proxy in _get_missing(self._stats, proxies):
            self._stats.pop(proxy)

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

    def get_random_address(self):
        self._auto_refresh()
        return random.choice(self.proxies)

    def get_pool(self):
        if self.__pool is None:
            if self._smart_holdout_start is None:
                self.__pool = _Pool(self, self._cooling_down, self._blacklist, self._stats)
            else:
                self.__pool = _Pool(
                    self, self._cooling_down, self._blacklist, self._stats,
                    smart_holdout=True, smart_holdout_start=self._smart_holdout_start,
                    smart_holdout_min=self._smart_holdout_min,
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
            self, proxies: "`Proxies` instance", cooling_down, blacklist, stats,
            smart_holdout=False, smart_holdout_start=None, smart_holdout_min=None,
    ):
        if smart_holdout:
            if smart_holdout_start in (None, 0):
                raise RuntimeError("Вы должны указать начальное время охлаждения")

        self._used = set()
        self._cond = threading.Condition()

        # более оптимальный способ заполнения, используется только для инициализации
        self._free = collections.deque(proxies.proxies)

        self._proxies = proxies
        self._cooling_down = cooling_down
        self._blacklist = blacklist
        self._stats = stats
        self._smart_holdout = smart_holdout
        self._smart_holdout_start = smart_holdout_start
        self._smart_holdout_min = smart_holdout_min or 0

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
            self._cooling_down.pop(proxy)
            if proxy not in self._blacklist:
                self._free.append(proxy)

    def _is_proxies_changed(self):
        return self._proxies._modified_at != self._proxies_modified_at

    def _remove_outdated(self):
        # список прокси изменился, оставляем только актуальные

        full_list = set(self._proxies)

        for proxy in _get_missing(self._blacklist, full_list):
            self._blacklist.pop(proxy)

        for proxy in _get_missing(self._cooling_down, full_list):
            self._cooling_down.pop(proxy)

        for proxy in _get_missing(self._used, full_list):
            self._used.remove(proxy)

        for proxy in _get_missing(self._stats, full_list):
            self._stats.pop(proxy)

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

        # универсальный способ сказать что статистика обновилась
        # тк без вызова метода .save будет работать и с обычным словарем (не только с JsonDict)
        self._stats[proxy] = proxy_stat

    def _get_next_holdout(self, prev_holdout, bad=False):
        """Рассчитывает время охлаждения.

        @param prev_holdout: предыдущее время охлаждения (нижняя граница)
        @param bad: True - вычисляем охлаждение для неудачи, иначе False
        @return: рекомендуемое время охлаждения в секундах
        """

        # Алгоритм основан на бинарном поиске,
        # в отличии от которого нам не известна верхняя граница

        lo = prev_holdout

        if bad:
            holdout = lo * 2
        else:
            # возвращаемся к предыдущей границе (lo / 2)
            # но с небольшим отступом - на середину отрезка [(lo / 2), lo]
            holdout = lo * 0.75

        return holdout

    def _get_last_holdout(self, proxy):
        proxy_stat = self._stats.get(proxy)
        if proxy_stat is None:
            return None

        return proxy_stat['last_holdout']

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

            if self._smart_holdout:
                _holdout = (
                    self._get_last_holdout(proxy) or
                    holdout or
                    self._smart_holdout_start
                )

                # Не позволяем границе опуститься слишком низко
                if _holdout < self._smart_holdout_min:
                    holdout = self._smart_holdout_min
                else:
                    _holdout = self._get_next_holdout(_holdout, bad=bad)
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


class Chain:
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

    def __del__(self):
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
