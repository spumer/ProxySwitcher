import sys

from . import stats


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
        raise_for_conn_problem=True, request_logging=True, log=None, **kw
    ):
        super().__init__(**kw)

        self.ssl_verify = ssl_verify
        self.timeout = timeout
        self.apparent_encoding = apparent_encoding
        self.raise_for_conn_problem = raise_for_conn_problem
        self._request_logging = request_logging
        self._log = log

        self._log_session_start()

    def _setdefault_resp_encoding(self, resp):
        if resp.encoding is None:
            resp.encoding = self.apparent_encoding

    def _update_params_defaults(self, params):
        params.setdefault('timeout', self.timeout)
        params.setdefault('verify', self.ssl_verify)

    def _log_session_start(self):
        if self._log is not None:
            self._log.info(
                "New session started: session=%r" % stats.get_session_ident(
                    self.session
                )
            )

    def switch_session(self):
        if self._request_logging:
            event = getattr(self.session, '__last_request_event', None)
            if event is not None:
                event.replace(switch=True)
                event.update_async()

        super().switch_session()
        self._log_session_start()

    def request(self, method, url, headers=None, data=None, **kw):
        from _УтилитыSbis import conn_problem_detector

        self._update_params_defaults(kw)

        exc_info = None
        ret_code = None
        try:
            with conn_problem_detector():
                resp = self.session.request(
                    method, url, headers=headers, data=data, **kw
                )
                ret_code = resp.status_code
                if self.raise_for_conn_problem:
                    resp.raise_for_status()
        except:
            exc_info = sys.exc_info()
            raise
        finally:
            if self._request_logging:
                event = stats.Event.from_partial(
                    self.session, method, url, data, headers, ret_code, exc_info=exc_info,
                    log=self._log,
                )
                event.create_async()
                self.session.__last_request_event = event

        self._setdefault_resp_encoding(resp)
        return resp

    def get(self, url, **kw):
        return self.request('GET', url, **kw)

    def post(self, url, **kw):
        return self.request('POST', url, **kw)
