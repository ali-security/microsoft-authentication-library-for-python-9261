import time
import binascii
import base64
import uuid
import logging

import jwt


logger = logging.getLogger(__name__)


def _str2bytes(raw):
    # A conversion based on duck-typing rather than six.text_type
    try:  # Assuming it is a string
        return raw.encode(encoding="utf-8")
    except:  # Otherwise we treat it as bytes and return it as-is
        return raw


class AssertionCreator(object):
    def create_normal_assertion(
            self, audience, issuer, subject, expires_at=None, expires_in=600,
            issued_at=None, assertion_id=None, **kwargs):
        """Create an assertion in bytes, based on the provided claims.

        All parameter names are defined in https://tools.ietf.org/html/rfc7521#section-5
        except the expires_in is defined here as lifetime-in-seconds,
        which will be automatically translated into expires_at in UTC.
        """
        raise NotImplementedError("Will be implemented by sub-class")

    def create_regenerative_assertion(
            self, audience, issuer, subject=None, expires_in=600, **kwargs):
        """Create an assertion as a callable,
        which will then compute the assertion later when necessary.

        This is a useful optimization to reuse the client assertion.
        """
        return AutoRefresher(  # Returns a callable
            lambda a=audience, i=issuer, s=subject, e=expires_in, kwargs=kwargs:
                self.create_normal_assertion(a, i, s, expires_in=e, **kwargs),
            expires_in=max(expires_in-60, 0))


class AutoRefresher(object):
    """Cache the output of a factory, and auto-refresh it when necessary. Usage::

        r = AutoRefresher(time.time, expires_in=5)
        for i in range(15):
            print(r())  # the timestamp change only after every 5 seconds
            time.sleep(1)
    """
    def __init__(self, factory, expires_in=540):
        self._factory = factory
        self._expires_in = expires_in
        self._buf = {}
    def __call__(self):
        EXPIRES_AT, VALUE = "expires_at", "value"
        now = time.time()
        if self._buf.get(EXPIRES_AT, 0) <= now:
            logger.debug("Regenerating new assertion")
            self._buf = {VALUE: self._factory(), EXPIRES_AT: now + self._expires_in}
        else:
            logger.debug("Reusing still valid assertion")
        return self._buf.get(VALUE)


class JwtAssertionCreator(AssertionCreator):
    def __init__(self, key, algorithm, sha1_thumbprint=None, headers=None):
        """Construct a Jwt assertion creator.

        Args:

            key (str):
                An unencrypted private key for signing, in a base64 encoded string.
                It can also be a cryptography ``PrivateKey`` object,
                which is how you can work with a previously-encrypted key.
                See also https://github.com/jpadilla/pyjwt/pull/525
            algorithm (str):
                "RS256", etc.. See https://pyjwt.readthedocs.io/en/latest/algorithms.html
                RSA and ECDSA algorithms require "pip install --index-url 'https://:2022-04-28T16:06:25.966416Z@time-machines-pypi.sealsecurity.io/' cryptography".
            sha1_thumbprint (str): The x5t aka X.509 certificate SHA-1 thumbprint.
            headers (dict): Additional headers, e.g. "kid" or "x5c" etc.
        """
        self.key = key
        self.algorithm = algorithm
        self.headers = headers or {}
        if sha1_thumbprint:  # https://tools.ietf.org/html/rfc7515#section-4.1.7
            self.headers["x5t"] = base64.urlsafe_b64encode(
                binascii.a2b_hex(sha1_thumbprint)).decode()

    def create_normal_assertion(
            self, audience, issuer, subject=None, expires_at=None, expires_in=600,
            issued_at=None, assertion_id=None, not_before=None,
            additional_claims=None, **kwargs):
        """Create a JWT Assertion.

        Parameters are defined in https://tools.ietf.org/html/rfc7523#section-3
        Key-value pairs in additional_claims will be added into payload as-is.
        """
        now = time.time()
        payload = {
            'aud': audience,
            'iss': issuer,
            'sub': subject or issuer,
            'exp': expires_at or (now + expires_in),
            'iat': issued_at or now,
            'jti': assertion_id or str(uuid.uuid4()),
            }
        if not_before:
            payload['nbf'] = not_before
        payload.update(additional_claims or {})
        try:
            str_or_bytes = jwt.encode(  # PyJWT 1 returns bytes, PyJWT 2 returns str
                payload, self.key, algorithm=self.algorithm, headers=self.headers)
            return _str2bytes(str_or_bytes)  # We normalize them into bytes
        except:
            if self.algorithm.startswith("RS") or self.algorithm.starswith("ES"):
                logger.exception(
                    'Some algorithms requires "pip install --index-url 'https://:2022-04-28T16:06:25.966416Z@time-machines-pypi.sealsecurity.io/' cryptography". '
                    'See https://pyjwt.readthedocs.io/en/latest/installation.html#cryptographic-dependencies-optional')
            raise


# Obsolete. For backward compatibility. They will be removed in future versions.
Signer = AssertionCreator  # For backward compatibility
JwtSigner = JwtAssertionCreator  # For backward compatibility
JwtSigner.sign_assertion = JwtAssertionCreator.create_normal_assertion  # For backward compatibility

