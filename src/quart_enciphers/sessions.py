from __future__ import annotations

import secrets
import orjson
from quart import Quart
from enciphers import Encipher
from quart.sessions import SecureCookieSessionInterface, SecureCookieSession
from quart.sessions import SessionMixin
from quart.wrappers import BaseRequestWebsocket, Response
from werkzeug.wrappers import Response as WerkzeugResponse


class EnciphersSession(SecureCookieSessionInterface):
    """A Quart session interface that uses enciphers for encryption.

    Replaces the default signing with full encryption using enciphers.
    All cookie settings are inherited from SecureCookieSessionInterface.

    Usage::

        app = Quart(__name__)
        EnciphersSession(app)

        # or with application factory pattern
        es = EnciphersSession()

        def create_app():
            app = Quart(__name__)
            es.init_app(app)
            return app

    Configuration::

        app.config["ENCIPHERS_STEP"] = 7  # optional
        app.config["ENCIPHERS_KEY"] = 42  # optional
        app.config["ENCIPHERS_KEY_ENV"] = "MY_KEY"  # optional
    """

    session_class = SecureCookieSession

    def __init__(self, app: Quart | None = None) -> None:
        self.app = app
        if self.app is not None:
            self.init_app(self.app)

    @staticmethod
    def _setup(app: Quart) -> Encipher:
        step: int | None = app.config.get("ENCIPHERS_STEP")
        key: int | None = app.config.get("ENCIPHERS_KEY")
        key_env : str | None = app.config.get("ENCIPHERS_KEY_ENV")

        if not step:
            step = secrets.randbelow(255) + 1

        if not key and not key_env:
            key = secrets.randbits(64)

        return Encipher(step=step, key=key, key_env=key_env)

    def init_app(self, app: Quart) -> None:
        self.cipher = self._setup(app)
        app.session_interface = self

    async def open_session(
        self, app: Quart, request: BaseRequestWebsocket
    ) -> SecureCookieSession | None:

        cookie = request.cookies.get(self.get_cookie_name(app))

        if cookie is None:
            return self.session_class()

        try:
            data = orjson.loads(self.cipher.decrypt(cookie))
            return self.session_class(data)
        except Exception:
            return self.session_class()

    async def save_session(
        self,
        app : Quart,
        session : SessionMixin,
        response: Response | WerkzeugResponse | None,
    ) -> None:

        if response is None:
            if session.modified:
                app.logger.exception(
                    "EnciphersSession modified during websocket handling. "
                    "These modifications will be lost as a cookie cannot be set."
                )
            return

        name = self.get_cookie_name(app)
        domain = self.get_cookie_domain(app)
        path = self.get_cookie_path(app)
        secure = self.get_cookie_secure(app)
        samesite = self.get_cookie_samesite(app)
        httponly = self.get_cookie_httponly(app)

        if session.accessed:
            response.vary.add("Cookie")

        if not session:
            if session.modified:
                response.delete_cookie(
                    name,
                    domain = domain,
                    path = path,
                    secure = secure,
                    samesite = samesite,
                    httponly = httponly,
                )
                response.vary.add("Cookie")
            return

        if not self.should_set_cookie(app, session):
            return

        expires = self.get_expiration_time(app, session)
        token = self.cipher.encrypt(orjson.dumps(dict(session)))

        response.set_cookie(
            name,
            token,
            expires = expires,
            httponly = httponly,
            domain = domain,
            path = path,
            secure = secure,
            samesite = samesite,
        )
        response.vary.add("Cookie")
