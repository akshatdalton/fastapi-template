from datetime import datetime
from typing import Any, Dict

import uvicorn
from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer

from token_verifier import VerifyToken

description = """Auth0-Getting-Started"""

app = FastAPI(
    debug=True,
    title="Auth0-Getting-Started",
    description=description,
    version="0.0.1",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

token_auth_scheme = HTTPBearer()


@app.get("/")
async def health_check():
    return {
        "message": f"Auth0-Getting-Started is up and well as of {datetime.utcnow()} UTC."
        f"{description}"
    }


@app.get("/api/public")
async def public_api() -> Dict[str, Any]:
    return {"status_code": 200, "message": "success from public api", "type": "public api"}


@app.get("/api/private")
async def private_api(token: str = Depends(token_auth_scheme)) -> Dict[str, Any]:
    result = VerifyToken(token.credentials).verify()
    return {"status_code": 200, "message": "success from private api", "type": "private api"}


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8080, reload=True)
