from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
import base64, os

app = FastAPI(title="ECDSA Signer", version="1.2.0")

@app.get("/")
def root():
    return {"status": "ok"}

def load_private_key():
    pem = os.environ.get("PRIVATE_KEY_PEM")
    if not pem:
        raise RuntimeError("PRIVATE_KEY_PEM env var not set")
    return serialization.load_pem_private_key(pem.encode("utf-8"), password=None)

@app.get("/pubkey.pem")
def pubkey_pem():
    key = load_private_key()
    pub = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    # texto plano para que el navegador no intente importarlo
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
    # valida input
    if not isinstance(req.canonical, str) or req.canonical == "":
        raise HTTPException(status_code=400, detail="canonical debe ser string no vacío")

    key = load_private_key()

    # firmamos SOLO el valor de 'canonical' en UTF-8
    signed_bytes = req.canonical.encode("utf-8")

    # ES384 = ECDSA P-384 + SHA-384
    signature = key.sign(signed_bytes, ec.ECDSA(hashes.SHA384()))

    return {
        "alg": "ES384",
        "curve": "P-384",
        "signature_der_base64": base64.b64encode(signature).decode(),
        "signed_bytes_base64": base64.b64encode(signed_bytes).decode(),
    }
