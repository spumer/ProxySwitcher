import cgi
import warnings


def get_encoding_from_headers(headers, rfc2616_missing_charset=None):
    """Returns encodings from given HTTP Header Dict.

    @param headers: dictionary to extract encoding from.
    @param rfc2616_missing_charset: use this encoding for text content by default
     if not set will be used ISO-8859-1
    """

    content_type = headers.get('content-type')

    if not content_type:
        return None

    content_type, params = cgi.parse_header(content_type)

    if 'charset' in params:
        return params['charset'].strip("'\"")

    if 'text' in content_type:
        if rfc2616_missing_charset is None:
            rfc2616_missing_charset = 'ISO-8859-1'

        return rfc2616_missing_charset

    return None


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
        self, ssl_verify=False, timeout=10, apparent_encoding=None, rfc2616_missing_charset=False,
        raise_conn_problem=True, raise_for_status=False,
        request_logger=None, **kw
    ):
        """
        @param ssl_verify: (см. Session.request)
        @param timeout: (см. Session.request)
        @param apparent_encoding: кодировка (предполагаемая) по умолчанию
        @param rfc2616_missing_charset: True - использовать кодировку по умолчанию согласно rfc2616,
            False - `apparent_encoding` по возможности
        @param raise_for_status: надо ли вызывать resp.raise_for_status при получении ответа
        @param request_logger: request_logging.Logger для логирования запросов
        """
        if 'request_logging' in kw:
            kw.pop('request_logging', None)
            warnings.warn(
                "`request_logging` flag has no effect and will be removed. "
                "To logging your requests use `request_logger` parameter",
                DeprecationWarning,
            )

        if 'log' in kw:
            kw.pop('log', None)
            warnings.warn(
                "`log` parameter has no effect and will be removed. "
                "To logging your requests use `request_logger` parameter",
                DeprecationWarning,
            )

        # _new_sess override require
        self._request_logger = request_logger

        super().__init__(**kw)

        self.ssl_verify = ssl_verify
        self.timeout = timeout
        self.apparent_encoding = apparent_encoding
        self.rfc2616_missing_charset = rfc2616_missing_charset

        self._raise_conn_problem = raise_conn_problem
        self._raise_for_status = raise_for_status

    def _new_sess(self):
        session = super()._new_sess()

        if self._request_logger:
            from . import request_logging
            request_logging.add_session_send_logging(session, logger=self._request_logger)

        return session

    def _setdefault_resp_encoding(self, resp):
        if not self.rfc2616_missing_charset:
            resp.encoding = get_encoding_from_headers(resp.headers, self.apparent_encoding)
        elif resp.encoding is None:
            resp.encoding = self.apparent_encoding

    def _update_params_defaults(self, params):
        params.setdefault('timeout', self.timeout)
        params.setdefault('verify', self.ssl_verify)

    def switch_session(self, bad=False, holdout=None, bad_reason=None):
        if self._request_logger:
            self._request_logger.before_switch_session(session=self)

        super().switch_session(bad=bad, holdout=holdout, bad_reason=bad_reason)

    def request(self, method, url, headers=None, data=None, **kw):
        from _УтилитыSbis import conn_problem_detector

        self._update_params_defaults(kw)

        def _request():
            resp = self.session.request(
                method, url, headers=headers, data=data, **kw
            )
            if self._raise_for_status:
                resp.raise_for_status()

            return resp

        if self._raise_conn_problem:
            with conn_problem_detector():
                resp = _request()
        else:
            resp = _request()

        self._setdefault_resp_encoding(resp)
        return resp

    def get(self, url, **kwargs):
        kwargs.setdefault('allow_redirects', True)
        return self.request('GET', url, **kwargs)

    def post(self, url, data=None, json=None, **kwargs):
        return self.request('POST', url, data=data, json=json, **kwargs)

    def options(self, url, **kwargs):
        kwargs.setdefault('allow_redirects', True)
        return self.request('OPTIONS', url, **kwargs)

    def head(self, url, **kwargs):
        kwargs.setdefault('allow_redirects', False)
        return self.request('HEAD', url, **kwargs)

    def put(self, url, data=None, **kwargs):
        return self.request('PUT', url, data=data, **kwargs)

    def patch(self, url, data=None, **kwargs):
        return self.request('PATCH', url,  data=data, **kwargs)

    def delete(self, url, **kwargs):
        return self.request('DELETE', url, **kwargs)
