from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
import base64, os
import json, math
from typing import Any

app = FastAPI(title="ECDSA Signer", version="1.4.0")

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

class SignFormatsResponse(BaseModel):
    alg: str
    curve: str
    signature_der_base64: str
    signature_p1363_base64: str
    signature_p1363_base64url: str
    signed_bytes_base64: str

class SignDigestRequest(BaseModel):
    # sha256 digest en base64 (estándar); exactamente 32 bytes al decodificar
    sha256_base64: str

class SignDigestResponse(BaseModel):
    alg: str
    curve: str
    digest_base64: str
    signature_der_base64: str
    signature_p1363_base64: str
    signature_p1363_base64url: str

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


# --- Canonical JSON helpers & endpoints ---

class CanonicalizeRequest(BaseModel):
    # JSON arbitrario que será canonizado
    json: Any


class CanonicalizeResponse(BaseModel):
    canonical: str


def _normalize_numbers(value: Any) -> Any:
    """
    Normaliza números para la canónica:
    - Convierte floats equivalentes a enteros (p.ej. 1.0) en int → 1
    - Mantiene ints y otros tipos sin cambios
    - Recorre recursivamente listas y diccionarios

    Nota: Esto no implementa JCS completo para todos los casos numéricos,
    pero evita representaciones como 1.0 cuando el valor es entero.
    """
    if isinstance(value, float):
        if math.isfinite(value) and value.is_integer():
            return int(value)
        return value
    if isinstance(value, dict):
        return {k: _normalize_numbers(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_normalize_numbers(v) for v in value]
    return value


def canonicalize_json(value: Any) -> str:
    """Devuelve el JSON canónico: llaves ordenadas, sin espacios innecesarios."""
    normalized = _normalize_numbers(value)
    try:
        # ensure_ascii=False para preservar Unicode; separadores compactos; llaves ordenadas
        return json.dumps(normalized, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    except TypeError as e:
        # Tipos no serializables (e.g. bytes) no son válidos para JSON
        raise HTTPException(status_code=400, detail=f"JSON no serializable: {str(e)}")


@app.post("/canonicalize", response_model=CanonicalizeResponse)
def canonicalize(req: CanonicalizeRequest):
    canonical = canonicalize_json(req.json)
    return {"canonical": canonical}


if __name__ == "__main__":
    # Permite ejecutar: python app.py
    # Respeta PORT si está definido (Heroku/Render/Cloud Run style)
    import uvicorn
    port_str = os.environ.get("PORT", "8000")
    try:
        port = int(port_str)
    except ValueError:
        port = 8000
    uvicorn.run("app:app", host="0.0.0.0", port=port, reload=False)

def _der_to_rs(der_signature: bytes) -> tuple[bytes, bytes]:
    # Parse SEQUENCE of two INTEGERs (r, s) from ASN.1 DER
    i = 0
    if i >= len(der_signature) or der_signature[i] != 0x30:
        raise ValueError("Not a DER SEQUENCE")
    i += 1
    if i >= len(der_signature):
        raise ValueError("Invalid DER length")
    length = der_signature[i]; i += 1
    if length & 0x80:
        n = length & 0x7F
        if i + n > len(der_signature):
            raise ValueError("Invalid DER length bytes")
        length = int.from_bytes(der_signature[i:i+n], "big"); i += n

    if i >= len(der_signature) or der_signature[i] != 0x02:
        raise ValueError("Expected INTEGER r")
    i += 1
    if i >= len(der_signature):
        raise ValueError("Invalid r length")
    rlen = der_signature[i]; i += 1
    r = der_signature[i:i+rlen]; i += rlen

    if i >= len(der_signature) or der_signature[i] != 0x02:
        raise ValueError("Expected INTEGER s")
    i += 1
    if i >= len(der_signature):
        raise ValueError("Invalid s length")
    slen = der_signature[i]; i += 1
    s = der_signature[i:i+slen]; i += slen

    # Left-strip zeros then pad to 32 bytes for P-256
    r = r.lstrip(b"\x00").rjust(32, b"\x00")
    s = s.lstrip(b"\x00").rjust(32, b"\x00")
    return r, s

@app.post("/sign/formats", response_model=SignFormatsResponse)
def sign_formats(req: SignRequest):
    if not isinstance(req.canonical, str) or req.canonical == "":
        raise HTTPException(status_code=400, detail="canonical debe ser string no vacío")

    key = load_private_key()
    data = req.canonical.encode("utf-8")
    signature_der = key.sign(data, ec.ECDSA(hashes.SHA256()))

    r, s = _der_to_rs(signature_der)
    rs = r + s

    return {
        "alg": "ES256",
        "curve": "secp256r1",
        "signature_der_base64": base64.b64encode(signature_der).decode(),
        "signature_p1363_base64": base64.b64encode(rs).decode(),
        "signature_p1363_base64url": base64.urlsafe_b64encode(rs).rstrip(b"=").decode(),
        "signed_bytes_base64": base64.b64encode(data).decode(),
    }

@app.post("/sign-digest", response_model=SignDigestResponse)
def sign_digest(req: SignDigestRequest):
    if not isinstance(req.sha256_base64, str) or req.sha256_base64 == "":
        raise HTTPException(status_code=400, detail="sha256_base64 debe ser string no vacío")
    try:
        digest = base64.b64decode(req.sha256_base64, validate=True)
    except Exception:
        raise HTTPException(status_code=400, detail="sha256_base64 no es base64 válido")
    if len(digest) != 32:
        raise HTTPException(status_code=400, detail="sha256_base64 debe decodificar a 32 bytes")

    key = load_private_key()
    # Sign prehashed digest explicitly using Prehashed
    signature_der = key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    r, s = _der_to_rs(signature_der)
    rs = r + s

    return {
        "alg": "ES256",
        "curve": "secp256r1",
        "digest_base64": base64.b64encode(digest).decode(),
        "signature_der_base64": base64.b64encode(signature_der).decode(),
        "signature_p1363_base64": base64.b64encode(rs).decode(),
        "signature_p1363_base64url": base64.urlsafe_b64encode(rs).rstrip(b"=").decode(),
    }


class SignJsonRequest(BaseModel):
    json: Any


class SignJsonResponse(BaseModel):
    alg: str
    curve: str
    canonical: str
    signature_der_base64: str
    signature_p1363_base64: str
    signature_p1363_base64url: str
    signed_bytes_base64: str


@app.post("/sign/json", response_model=SignJsonResponse)
def sign_json(req: SignJsonRequest):
    canonical = canonicalize_json(req.json)
    key = load_private_key()
    data = canonical.encode("utf-8")
    signature_der = key.sign(data, ec.ECDSA(hashes.SHA256()))
    r, s = _der_to_rs(signature_der)
    rs = r + s

    return {
        "alg": "ES256",
        "curve": "secp256r1",
        "canonical": canonical,
        "signature_der_base64": base64.b64encode(signature_der).decode(),
        "signature_p1363_base64": base64.b64encode(rs).decode(),
        "signature_p1363_base64url": base64.urlsafe_b64encode(rs).rstrip(b"=").decode(),
        "signed_bytes_base64": base64.b64encode(data).decode(),
    }
