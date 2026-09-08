import os

import jwt
from dotenv import load_dotenv
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWKClient


load_dotenv()

AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN")
AUTH0_AUDIENCE = os.getenv("AUTH0_AUDIENCE")
AUTH0_ALGORITHM = os.getenv("AUTH0_ALGORITHMS", "RS256")

AUTH0_ISSUER = f"https://{AUTH0_DOMAIN}/"
JWKS_URL = f"{AUTH0_ISSUER}.well-known/jwks.json"

security = HTTPBearer(auto_error=False)
jwks_client = PyJWKClient(JWKS_URL)


async def verify_token(
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token is required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials

    try:
        signing_key = jwks_client.get_signing_key_from_jwt(token).key

        payload = jwt.decode(
            token,
            signing_key,
            algorithms=[AUTH0_ALGORITHM],
            audience=AUTH0_AUDIENCE,
            issuer=AUTH0_ISSUER,
        )

        return payload

    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )

    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid access token",
            headers={"WWW-Authenticate": "Bearer"},
        )


def require_permission(required_permission: str):
    async def permission_checker(
        token_payload: dict = Depends(verify_token),
    ):
        permissions = token_payload.get("permissions", [])
        scopes = token_payload.get("scope", "").split()

        if (
            required_permission not in permissions
            and required_permission not in scopes
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing permission: {required_permission}",
            )

        return token_payload

    return permission_checker