from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
import base64, os

app = FastAPI(title="ECDSA Signer", version="1.4.0")

def load_private_key():
    pem = os.environ.get("PRIVATE_KEY_PEM")
    if not pem:
        raise RuntimeError("PRIVATE_KEY_PEM env var not set")
    key = serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
    # Soporta P-384 (secp384r1) para Círculo de Crédito
    if not isinstance(key.curve, (ec.SECP256R1, ec.SECP384R1)):
        raise RuntimeError("Private key must be P-256 (secp256r1) or P-384 (secp384r1)")
    return key

def get_curve_info(key):
    """Retorna información sobre la curva de la llave"""
    if isinstance(key.curve, ec.SECP256R1):
        return {"alg": "ES256", "curve": "secp256r1", "size": 32}
    elif isinstance(key.curve, ec.SECP384R1):
        return {"alg": "ES384", "curve": "secp384r1", "size": 48}
    else:
        raise RuntimeError("Unsupported curve")

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
    curve_info = get_curve_info(key)
    data = req.canonical.encode("utf-8")

    # SHA-256 para ambas curvas (como requiere Círculo)
    signature = key.sign(data, ec.ECDSA(hashes.SHA256()))

    return {
        "alg": curve_info["alg"],
        "curve": curve_info["curve"],
        "signature_der_base64": base64.b64encode(signature).decode(),
        "signed_bytes_base64": base64.b64encode(data).decode(),
    }

def _der_to_rs(der_signature: bytes, size: int = 32) -> tuple[bytes, bytes]:
    """Parse SEQUENCE of two INTEGERs (r, s) from ASN.1 DER
    
    Args:
        der_signature: DER encoded signature
        size: Size in bytes for the curve (32 for P-256, 48 for P-384)
    """
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

    # Remove leading zeros ONLY if they're not needed for sign extension
    # For positive integers, remove leading 0x00 if present
    if len(r) > 0 and r[0] == 0x00 and (len(r) == 1 or r[1] & 0x80 == 0):
        r = r[1:]
    if len(s) > 0 and s[0] == 0x00 and (len(s) == 1 or s[1] & 0x80 == 0):
        s = s[1:]
    
    # Pad to size with zeros on the LEFT (big-endian)
    r = r.rjust(size, b"\x00")[:size]
    s = s.rjust(size, b"\x00")[:size]
    
    return r, s

@app.post("/sign/formats", response_model=SignFormatsResponse)
def sign_formats(req: SignRequest):
    if not isinstance(req.canonical, str) or req.canonical == "":
        raise HTTPException(status_code=400, detail="canonical debe ser string no vacío")

    key = load_private_key()
    curve_info = get_curve_info(key)
    data = req.canonical.encode("utf-8")
    signature_der = key.sign(data, ec.ECDSA(hashes.SHA256()))

    r, s = _der_to_rs(signature_der, curve_info["size"])
    rs = r + s

    return {
        "alg": curve_info["alg"],
        "curve": curve_info["curve"],
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
    curve_info = get_curve_info(key)
    # Sign prehashed digest explicitly using Prehashed
    signature_der = key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    r, s = _der_to_rs(signature_der, curve_info["size"])
    rs = r + s

    return {
        "alg": curve_info["alg"],
        "curve": curve_info["curve"],
        "digest_base64": base64.b64encode(digest).decode(),
        "signature_der_base64": base64.b64encode(signature_der).decode(),
        "signature_p1363_base64": base64.b64encode(rs).decode(),
        "signature_p1363_base64url": base64.urlsafe_b64encode(rs).rstrip(b"=").decode(),
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
