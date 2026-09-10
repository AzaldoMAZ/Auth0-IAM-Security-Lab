from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from auth import require_permission


app = FastAPI(
    title="Auth0 FastAPI Lab",
    description="A FastAPI application protected using Auth0.",
    version="1.0.0",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["GET"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.get("/")
async def root():
    return {
        "message": "Auth0 FastAPI Lab is running",
        "status": "healthy",
    }


@app.get("/api/public")
async def public_endpoint():
    return {
        "message": "This is a public endpoint. No access token is required."
    }


@app.get("/api/protected")
async def protected_endpoint(
    token_payload: dict = Depends(
        require_permission("read:protected")
    ),
):
    return {
        "message": "You have permission to access this protected endpoint.",
        "user_id": token_payload.get("sub"),
        "required_permission": "read:protected",
    }


@app.get("/api/sensitive")
async def sensitive_endpoint(
    token_payload: dict = Depends(
        require_permission("read:sensitive")
    ),
):
    mfa_completed = token_payload.get(
        "https://auth0-fastapi-lab/mfa"
    )

    if mfa_completed is not True:
        raise HTTPException(
            status_code=403,
            detail="MFA verification is required for this endpoint.",
        )

    return {
        "message": "Sensitive API access granted after MFA verification.",
        "user_id": token_payload.get("sub"),
        "required_permission": "read:sensitive",
        "mfa_verified": True,
    }
    