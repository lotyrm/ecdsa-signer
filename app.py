from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
import base64, os, json

app = FastAPI(title="ECDSA Signer", version="1.1.0")

# --- Health check ---
@app.get("/")
def root():
    return {"status": "ok"}

# --- Carga de la llave privada desde variable de entorno ---
def load_private_key():
    pem = os.environ.get("PRIVATE_KEY_PEM")
    if not pem:
        raise RuntimeError("PRIVATE_KEY_PEM env var not set")
    # PEM multilínea pegado tal cual en Railway (BEGIN/END). Sin comillas, sin "\n".
    return serialization.load_pem_private_key(pem.encode("utf-8"), password=None)

# --- Rutas de diagnóstico (puedes borrarlas después de verificar) ---

# Llave pública en PEM (lo que realmente usa el servidor)
@app.get("/pubkey.pem")
def pubkey_pem():
    key = load_private_key()
    pub = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return Response(content=pub, media_type="application/x-pem-file")

# Llave pública en JWK (x,y base64url) por si la necesitas
@app.get("/pubkey.jwk")
def pubkey_jwk():
    key = load_private_key()
    nums = key.public_key().public_numbers()
    x = nums.x.to_bytes(48, "big")  # P-384 => 48 bytes
    y = nums.y.to_bytes(48, "big")
    b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    return {"kty": "EC", "crv": "P-384", "x": b64u(x), "y": b64u(y)}

# --- Modelos de request/response ---
class SignRequest(BaseModel):
    canonical: str  # el string exacto a firmar

class SignResponse(BaseModel):
    alg: str
    curve: str
    signature_der_base64: str
    signed_bytes_base64: str

# --- Endpoint principal de firma ---
@app.post("/sign", response_model=SignResponse)
def sign(req: SignRequest):
    key = load_private_key()

    # Qué bytes se firman: aquí firmamos SOLO el campo "canonical"
    signed_bytes = req.canonical.encode("utf-8")

    # ES384 = ECDSA P-384 con SHA-384 (lo correcto para P-384)
    signature = key.sign(signed_bytes, ec.ECDSA(hashes.SHA384()))

    return {
        "alg": "ES384",
        "curve": "P-384",
        "signature_der_base64": base64.b64encode(signature).decode(),
        "signed_bytes_base64": base64.b64encode(signed_bytes).decode(),
    }

# --- Endpoint de depuración (opcional) que además entrega P-1363 ---
@app.post("/sign-debug")
def sign_debug(req: SignRequest):
    key = load_private_key()

    if "canonical" not in req.model_dump() or not isinstance(req.canonical, str):
        raise HTTPException(status_code=400, detail="Falta 'canonical' (string) en el JSON")

    signed_bytes = req.canonical.encode("utf-8")
    signature = key.sign(signed_bytes, ec.ECDSA(hashes.SHA384()))

    r, s = utils.decode_dss_signature(signature)
    r_b = r.to_bytes(48, "big")
    s_b = s.to_bytes(48, "big")
    p1363 = r_b + s_b

    return {
        "alg": "ES384",
        "curve": "P-384",
        "what_signed": "req.canonical",
        "hash": "SHA-384",
        "signed_bytes_base64": base64.b64encode(signed_bytes).decode(),
        "signature_der_base64": base64.b64encode(signature).decode(),
        "signature_p1363_base64url": base64.urlsafe_b64encode(p1363).rstrip(b"=").decode(),
    }

