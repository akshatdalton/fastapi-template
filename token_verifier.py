from dataclasses import dataclass

import jwt

import env_constants as env_consts
from config_parser_utils import ConfigParserUtils

cp = ConfigParserUtils()


@dataclass
class Auth0Credentials:
    domain: str
    api_audience: str
    algorirthms: str
    issuer: str


class VerifyToken:
    """Does all the token verification using PyJWT"""

    def __init__(self, token):
        self.token = token
        self._creds = VerifyToken._get_credentials()
        print("self._creds = ", self._creds)

        # This gets the JWKS from a given URL and does processing so you can
        # use any of the keys available
        jwks_url = f"https://{self._creds.domain}/.well-known/jwks.json"
        self.jwks_client = jwt.PyJWKClient(jwks_url)

    @staticmethod
    def _get_credentials():
        return Auth0Credentials(
            domain=cp.get_subsection(
                env_consts.AUTH0_CREDENTIALS, env_consts.AUTH0_DOMAIN
            ),
            api_audience=cp.get_subsection(
                env_consts.AUTH0_CREDENTIALS, env_consts.AUTH0_API_AUDIENCE
            ),
            algorirthms=cp.get_subsection(
                env_consts.AUTH0_CREDENTIALS, env_consts.AUTH0_ALGORITHMS
            ),
            issuer=cp.get_subsection(
                env_consts.AUTH0_CREDENTIALS, env_consts.AUTH0_ISSUER
            ),
        )

    def verify(self):
        # This gets the 'kid' from the passed token
        try:
            self.signing_key = self.jwks_client.get_signing_key_from_jwt(self.token).key
        except jwt.exceptions.PyJWKClientError as error:
            return {"status": "error", "msg": error.__str__()}
        except jwt.exceptions.DecodeError as error:
            return {"status": "error", "msg": error.__str__()}

        try:
            payload = jwt.decode(
                self.token,
                self.signing_key,
                algorithms=self._creds.algorirthms,
                audience=self._creds.api_audience,
                issuer=self._creds.issuer,
            )
        except Exception as e:
            return {"status": "error", "message": str(e)}

        return payload
