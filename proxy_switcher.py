# encoding: utf-8

import random


class ProxySwitcher:
    """
    Не является потокобезопасным.
    """

    def __init__(self, proxies, proxy_gw=None, proxy_hops=1):
        """
        :param proxies: адреса прокси серверов
        :param proxy_gw: прокси-сервер, который должен стоять во главе цепочки
         (все запросы к другим прокси-серверам будут проходить через него)
        :param proxy_hops: количество звеньев в цепи прокси ("прыжков"). `proxy_gw` не учитывается.
        """

        proxy_count = len(proxies)
        assert proxy_hops <= proxy_count, "Incorrect hops count: %r > %r" % (proxy_hops, proxy_count)

        self.proxies = proxies
        self.proxy_gw = proxy_gw
        self.hops = proxy_hops

        self._path = []
        self.switch()

    def get_random_address(self):
        return self.proxies[
            random.randint(1, len(self.proxies)) - 1
        ]

    def get_random_addresses(self, count):
        return random.sample(self.proxies, count)

    def switch(self):
        self._path.clear()

        if self.proxy_gw:
            self._path.append(self.proxy_gw)

        if self.hops == 1:
            # optimize common case
            self._path.extend((self.get_random_address(),))
        else:
            self._path.extend(self.get_random_addresses(self.hops))

    def get_adapter(self):
        import socks.adapters
        return socks.adapters.ChainedProxyHTTPAdapter(chain=self._path)

    def get_opener(self):
        import socks.handlers
        return NotImplemented