
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import jwt

ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-q9bbgzxp.apps.exam.local"

PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""

app = FastAPI(title="JWT Verification Service")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class VerifyRequest(BaseModel):
    token: str = Field(min_length=1)


class VerifyResponse(BaseModel):
    valid: bool
    email: str | None = None
    sub: str | None = None
    aud: str | None = None


@app.post("/verify", response_model=VerifyResponse)
async def verify_token(request: VerifyRequest):
    try:
        claims = jwt.decode(
            request.token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=AUDIENCE,
            options={
                "require": ["exp", "iss", "aud", "sub", "email"],
            },
        )

        # Require the audience claim to match exactly.
        if claims.get("aud") != AUDIENCE:
            return JSONResponse(
                status_code=401,
                content={"valid": False},
            )

        return VerifyResponse(
            valid=True,
            email=claims["email"],
            sub=claims["sub"],
            aud=claims["aud"],
        )

    except Exception:
        return JSONResponse(
            status_code=401,
            content={"valid": False},
        )


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}
