from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
import base64, os

# Soporta P-256 (ES256) y P-384 (ES384) automáticamente
app = FastAPI(title="ECDSA Signer", version="1.3.0")

def load_private_key():
    pem = os.environ.get("PRIVATE_KEY_PEM")
    if not pem:
        raise RuntimeError("PRIVATE_KEY_PEM env var not set")
    try:
        return serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
    except Exception as e:
        raise RuntimeError(f"Could not deserialize key data: {e}")

def pick_alg_and_hash(key):
    # Detecta la curva y escoge el hash correcto
    if isinstance(key.curve, ec.SECP256R1):
        return ("ES256", "secp256r1", hashes.SHA256())
    if isinstance(key.curve, ec.SECP384R1):
        return ("ES384", "secp384r1", hashes.SHA384())
    raise RuntimeError("Unsupported EC curve; use P-256 (secp256r1) or P-384 (secp384r1)")

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
    # Texto plano para verlo en navegador/curl
    return Response(content=pub, media_type="text/plain; charset=us-ascii")

class SignRequest(BaseModel):
    canonical: str  # string exacto a firmar, tal cual

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
    alg, curve_name, hash_obj = pick_alg_and_hash(key)

    signed_bytes = req.canonical.encode("utf-8")
    signature_der = key.sign(signed_bytes, ec.ECDSA(hash_obj))

    return {
        "alg": alg,
        "curve": curve_name,
        "signature_der_base64": base64.b64encode(signature_der).decode(),
        "signed_bytes_base64": base64.b64encode(signed_bytes).decode(),
    }
