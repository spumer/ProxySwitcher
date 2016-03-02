import os
import sys
import time
import logging
import datetime
import threading
import collections
import urllib.parse
import concurrent.futures

import sql
import exc_matcher
import _УтилитыSbis
import socks.adapters


_boot_time = str(time.time()).replace('.', '')


_Event = collections.namedtuple('_Event', [
    'thread', 'session', 'method', 'hostname',
    'url', 'query', 'data', 'headers', 'ret_code',
    'exc_type', 'exc_msg', 'proxy', 'created_at', 'switch'
])


def get_current_thread_ident():
    return '%s%s%s' % (_boot_time, os.getpid(), threading.current_thread().ident)


def get_session_ident(session, thread_ident=None):
    if thread_ident is None:
        thread_ident = get_current_thread_ident()

    return '{thread_ident}{session_id}'.format(
        thread_ident=thread_ident,
        session_id=id(session),
    )


class Event:
    default_log = logging.getLogger(__name__)
    _executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)

    def __init__(self, *args, pk=None, log=None, **kw):
        event = _Event(*args, **kw)

        if log is None:
            log = self.default_log

        self.log = log
        self._event = event
        self._event_pk = pk

    @staticmethod
    def _prepare_exc(exc_info=None):
        if exc_info is None:
            exc_info = sys.exc_info()

        if exc_info is None or not all(exc_info):
            return None, None

        exc_type, exc, _ = exc_info
        exc_msg = _УтилитыSbis.format_exception(exc)

        return exc_matcher.get_fqn(exc_type), exc_msg

    @staticmethod
    def _prepare_headers(request_headers=None, session_headers=None):
        if session_headers is None:
            return request_headers

        if request_headers is None:
            return session_headers

        merged_headers = dict(session_headers.items())
        merged_headers.update(request_headers)

        # sort headers by header lower name
        return collections.OrderedDict(
            (name.title(), value)
            for name, value in sorted(merged_headers.items(), key=lambda x: x[0].lower())
            if value is not None
        )

    @staticmethod
    def _extract_session_proxy_addr(session, scheme):
        adapter = session.adapters.get(scheme + '://')
        if adapter is None or not isinstance(adapter, socks.adapters.ChainedProxyHTTPAdapter):
            return None

        proxy = adapter._last_hop
        if proxy is None:
            return None

        return proxy.addr

    def as_dict(self):
        return self._event._asdict()

    def unwrap(self):
        return self._event

    def replace(self, **kw):
        self._event = self._event._replace(**kw)

    @classmethod
    def from_partial(
        cls, session, method, url, data=None, request_headers=None,
        ret_code=None, exc_type=None, exc_msg=None,
        created_at=None, switch=False, exc_info=None, **kw
    ):
        thread_ident = get_current_thread_ident()

        headers = cls._prepare_headers(request_headers, session.headers) or None
        if headers is not None:
            headers = str(headers)

        session_ident = get_session_ident(session, thread_ident)

        parsed_url = urllib.parse.urlparse(url)

        hostname = parsed_url.netloc
        query = parsed_url.query or None
        url = urllib.parse.urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, '', '', ''))

        if exc_type is None and exc_msg is None:
            exc_type, exc_msg = cls._prepare_exc(exc_info)

        if created_at is None:
            created_at = datetime.datetime.now()

        proxy = cls._extract_session_proxy_addr(session, parsed_url.scheme)

        return cls(
            thread_ident, session_ident, method,
            hostname, url, query, data, headers,
            ret_code, exc_type, exc_msg, proxy, created_at,
            switch, **kw
        )

    def log_future_exception(self, fut):
        exc = fut.exception()
        if exc is None:
            return

        msg = _УтилитыSbis.format_exception(exc)
        self.log.error(msg)

    def update(self):
        if self._event_pk is None:
            raise RuntimeError("You can't update unbounded event: pk is None!")

        sql.update(
            '_proxy_switcher_log',
            params=self.as_dict(),
            where={'@_proxy_switcher_log': self._event_pk}
        )

    def update_async(self):
        fut = self._executor.submit(self.update)
        fut.add_done_callback(self.log_future_exception)

    def create(self):
        self._event_pk = sql.query_scalar(
            '''
            INSERT INTO "_proxy_switcher_log" (
             "thread", "session", "method", "hostname", "url", "query",
             "data", "headers", "ret_code", "exc_type", "exc_msg", "proxy", "created_at", "switch"
            ) VALUES (
             {thread}, {session}, {method}, {hostname}, {url}, {query},
             {data}, {headers}, {ret_code}, {exc_type}, {exc_msg}, {proxy}, {created_at}, {switch}
            ) RETURNING "@_proxy_switcher_log"
            ''',
            params=self.as_dict(),
        )

    def create_async(self):
        fut = self._executor.submit(self.create)
        fut.add_done_callback(self.log_future_exception)
