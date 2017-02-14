"""
Пакет предназначен для работы со списками прокси.

Основные возможности:
1. Интеграция с `urllib.request` и `requests.Session`
2. Использование шлюза (прокси-сервера) для подключения к конечному прокси-серверу
3. Полу-автоматическая смена адреса (через вызов `Chain.switch` или `Client.switch_session`)
4. Работа со списком как с пулом:
 * Получение/освобождение адреса через методы acquire/release
 * Возврат адреса с его последующим охлаждением
    (время задается в секундах, по истечении которого адрес снова может быть взят из пула)
 * Возврат адреса в черный список
5. Логирование всех запросов (только для `requests.Session`)


Создание списка прокси:

!! Если вы планируете использовать его как пул, по возможности вы должны создать не более одного экземпляра

    * Из обычного списка
    proxies = proxy_switcher.chain.Proxies(['proxy-server.com:8080'])

    * Из файла:
    proxies = proxy_switcher.chain.Proxies(proxies_file='./proxy_list.txt')

    * По ссылке:
    proxies = proxy_switcher.chain.Proxies(proxies_url='http://proxy-list.example.com')

    * По ссылке через proxy:
    proxies = proxy_switcher.chain.Proxies(
        proxies_url='http://proxy-list.example.com',
        proxies_url_gateway='http://proxy.example.com'
    )

    * Из json (подробнее см. описание метода)
    proxies = proxy_switcher.chain.Proxies.from_cfg_string('''{
        "list": ["proxy-server.com:8080"]
    }''')

Для удобного использования реализован объект `proxy_switcher.chain.Chain` (с англ. - Цепь)

Создание:
    proxy_chain = proxy_switcher.chain.Chain(proxies)

    # Работаем как с пулом
    proxy_chain = proxy_switcher.chain.Chain(proxies, use_pool=True)
    (для более подробной информации см. ниже)

    # Указываем шлюз (все запросы к прокси-серверу будут отправляться от имени этого адреса)
    proxy_chain = proxy_switcher.chain.Chain(proxies, proxy_gw='socks5://dts-proxy2.unix.tensor.ru:9999')


Использование:
    * Вручную
    import requests

    session = requests.Session()
    proxy_chain.wrap_session(session)

    session.get('http://myip.ru')

    * Через `proxy_switcher.client.Client`
    client = proxy_switcher.client.Client(proxy_chain=proxy_chain)
    client.get('http://myip.ru')


Чтобы сменить адрес:
    * Вручную
    proxy_chain.switch()
    proxy_chain.wrap_session(session)  # !! важный момент, без этого работать не будет!

    * Через `proxy_switcher.client.Client`
    client.switch_session()


Для urllib.request:
    import urllib.request

    def _build_opener():
        handlers = [
            urllib.request.HTTPCookieProcessor,
            # Или любые другие ваши хендлеры
        ]

        handlers.append(proxy_chain.get_handler())

        return urllib.request.build_opener(*handlers)

    opener = _build_opener()
    opener.open('http://myip.ru')

    proxy_chain.switch()
    # Пересоздаем, тк пока нет другого способа
    opener = _build_opener()

Логирование запросов (включено по умолчанию):
Вся информация о запросе будет записываться в фоне в отдельную таблицу "_proxy_switcher_log"
Чтобы отключить логирование необходимо явно передать ключ:

    client = proxy_switcher.client.Client(request_logging=False)


Pool (пул) прокси:

Для работы с пулом рекомендуется использовать объект `proxy_switcher.chain.Chain`,
тк он гарантирует возвращение прокси в пул при освобождении ресурсов.

Блеклисты, охлаждение и статистика

По умолчанию все данные находятся только в памяти. Чтобы сделать списки постоянными
и не зависеть от перезапусков, достаточно указать путь(-и) до файла(-ов).

    proxies = proxy_switcher.chain.Proxies.from_cfg_string('''{
        "blacklist": "./proxy_blacklist.txt",
        "cooldown": "./proxy_cooldown.txt",
        "stats": "./proxy_stats.txt"
    }''')

Основные правила:

1. Наличие прокси на охлаждении _гарантирует_, что он не будет использован до истечения указанного периода
 (наличие прокси в черном списке никак на это не влияет!)

2. Наличие прокси в черном списке _гарантирует_, что он не будет использован пока есть свободные прокси
2.1 Прокси будет изъят из черного списка при отсутствии свободных прокси

* Чтобы поместить прокси на охлаждение на 30 секунд:
    client.switch_session(holdout=30)
    или
    proxy_chain.switch(holdout=30)


* Чтобы поместить прокси в черный список:
    client.switch_session(bad=True) или
    client.switch_session(bad=True, bad_reason="Причина")
    или
    proxy_chain.switch(bad=True) или
    proxy_chain.switch(bad=True, bad_reason="Причина")

Соответственно можно комбинировать - помещать прокси в оба списка.

По умолчанию получение адреса может длиться сколь угодно долго, чтобы ограничить время получения адреса
можно указать таймаут:

    proxy_chain = proxy_switcher.chain.Chain(proxies, use_pool=True, pool_acquire_timeout=5)

Тогда по истечении этого времени будет брошено исключение `NoFreeProxies` (см. proxy_switcher.errors)


Changelog:
   1.0.0 - Initial release
   1.1.0 - Добавлена возможность одновременного использования нескольких пулов - MultiChain;
   Улучшена работа алгоритма "smart holdout" (+ новая опция 'smart_holdout_max');
   Добавлены опции: 'default_holdout' и 'default_bad_holdout' для интервала охлаждения по умолчанию

"""


from .chain import Proxies, Chain, MultiChain, ProxyURLRefreshError
from .client import Client


__version__ = '1.1.0'
