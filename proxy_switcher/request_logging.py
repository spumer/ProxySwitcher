import sys
import types

import logging


class Logger:
    def send(self, session, request, resp=None, exc_info=None):
        pass

    def before_switch_session(self, session, *args, **kw):
        pass


def add_session_send_logging(session, logger: Logger):
    def _wrap_send(self, request, **kw):
        resp = None
        exc_info = None
        try:
            resp = self.__send_orig(request, **kw)
            return resp
        except:
            exc_info = sys.exc_info()
            raise
        finally:
            logger.send(session=self, request=request, resp=resp, exc_info=exc_info)

    session.__send_orig = session.send
    session.send = types.MethodType(_wrap_send, session)
