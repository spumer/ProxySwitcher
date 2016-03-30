from . import stats


class _RequestsClient:
    def __init__(self, proxy_chain=None, default_headers=None):
        default_headers_ = self._make_default_headers()
        if default_headers is not None:
            default_headers_.update(default_headers)

        self.proxy_chain = proxy_chain
        self.default_headers = default_headers_

        self._session = None

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

    @property
    def session(self):
        if self._session is None or getattr(self._session, '_proxy_sw_closed', False):
            self._session = self._new_sess()
        return self._session

    def switch_session(self, bad=False, holdout=None, bad_reason=None):
        old_session = self.session
        try:
            if self.proxy_chain:
                self.proxy_chain.switch(bad=bad, holdout=holdout, bad_reason=bad_reason)

            self._session = self._new_sess()
        finally:
            # original requests session does not have `closed` attr
            old_session._proxy_sw_closed = True
            old_session.close()


class Client(_RequestsClient):
    def __init__(
        self, ssl_verify=True, timeout=10, apparent_encoding=None,
        raise_for_conn_problem=True, request_logging=True, log=None, **kw
    ):
        # _new_sess override require
        self._request_logging = request_logging
        self._log = log

        super().__init__(**kw)

        self.ssl_verify = ssl_verify
        self.timeout = timeout
        self.apparent_encoding = apparent_encoding
        self.raise_for_conn_problem = raise_for_conn_problem

    def _new_sess(self):
        session = super()._new_sess()

        if self._request_logging:
            stats.add_session_send_logging(session, log=self._log)
            if self._log is not None:
                self._log.info(
                    "New session started: session=%r" % stats.get_session_ident(
                        session
                    )
                )

        return session

    def _setdefault_resp_encoding(self, resp):
        if resp.encoding is None:
            resp.encoding = self.apparent_encoding

    def _update_params_defaults(self, params):
        params.setdefault('timeout', self.timeout)
        params.setdefault('verify', self.ssl_verify)

    def switch_session(self, bad=False, holdout=None, bad_reason=None):
        if self._request_logging:
            event = getattr(self.session, '__last_request_event', None)
            if event is not None:
                event.replace(switch=True)
                event.update_async()

        super().switch_session(bad=bad, holdout=holdout, bad_reason=bad_reason)

    def request(self, method, url, headers=None, data=None, **kw):
        from _УтилитыSbis import conn_problem_detector

        self._update_params_defaults(kw)

        with conn_problem_detector():
            resp = self.session.request(
                method, url, headers=headers, data=data, **kw
            )
            if self.raise_for_conn_problem:
                resp.raise_for_status()

        self._setdefault_resp_encoding(resp)
        return resp

    def get(self, url, **kw):
        return self.request('GET', url, **kw)

    def post(self, url, **kw):
        return self.request('POST', url, **kw)
