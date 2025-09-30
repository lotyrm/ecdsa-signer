from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
import base64, os

app = FastAPI(title="ECDSA Signer", version="1.3.0")

def load_private_key():
    pem = os.environ.get("PRIVATE_KEY_PEM")
    if not pem:
        raise RuntimeError("PRIVATE_KEY_PEM env var not set")
    key = serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
    # Debe ser P-256 para ES256
    if not isinstance(key.curve, ec.SECP256R1):
        raise RuntimeError("Private key must be P-256 (secp256r1) for ES256")
    return key

@app.get("/")
def root():
    return {"status": "ok"}

@app.get("/pubkey.pem")
def pubkey_pem():
    key = load_private_key()
    pub = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return Response(content=pub, media_type="text/plain; charset=us-ascii")

class SignRequest(BaseModel):
    canonical: str  # el string exacto a firmar

class SignResponse(BaseModel):
    alg: str
    curve: str
    signature_der_base64: str
    signed_bytes_base64: str

@app.post("/sign", response_model=SignResponse)
def sign(req: SignRequest):
    if not isinstance(req.canonical, str) or req.canonical == "":
        raise HTTPException(status_code=400, detail="canonical debe ser string no vacío")

    key = load_private_key()
    data = req.canonical.encode("utf-8")

    # ES256 = ECDSA P-256 + SHA-256
    signature = key.sign(data, ec.ECDSA(hashes.SHA256()))

    return {
        "alg": "ES256",
        "curve": "secp256r1",
        "signature_der_base64": base64.b64encode(signature).decode(),
        "signed_bytes_base64": base64.b64encode(data).decode(),
    }
