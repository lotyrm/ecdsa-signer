from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
import base64, os

app = FastAPI(title="ECDSA Signer", version="2.0.0")

def load_private_key():
    pem = os.environ.get("PRIVATE_KEY_PEM")
    if not pem:
        raise RuntimeError("PRIVATE_KEY_PEM env var not set")
    key = serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
    # Permitimos P-256 (ES256) o P-384 (ES384)
    if not isinstance(key.curve, (ec.SECP256R1, ec.SECP384R1)):
        raise RuntimeError("Private key must be P-256 (secp256r1) or P-384 (secp384r1)")
    return key


def _detect_params(key) -> tuple[str, str, hashes.HashAlgorithm, int]:
    # Devuelve (alg, curve_name, hash_alg, rs_len)
    if isinstance(key.curve, ec.SECP256R1):
        return "ES256", "secp256r1", hashes.SHA256(), 32
    if isinstance(key.curve, ec.SECP384R1):
        return "ES384", "secp384r1", hashes.SHA384(), 48
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


class SignJoseResponse(BaseModel):
    alg: str
    curve: str
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

    alg, curve_name, hash_alg, _ = _detect_params(key)
    signature = key.sign(data, ec.ECDSA(hash_alg))

    return {
        "alg": alg,
        "curve": curve_name,
        "signature_der_base64": base64.b64encode(signature).decode(),
        "signed_bytes_base64": base64.b64encode(data).decode(),
    }

def _der_to_rs(der_signature: bytes, expected_length: int) -> tuple[bytes, bytes]:
    # Parse SEQUENCE of two INTEGERs (r, s) from ASN.1 DER, con padding fijo
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

    # Left-strip zeros then pad a longitud fija (32 para P-256, 48 para P-384)
    r = r.lstrip(b"\x00").rjust(expected_length, b"\x00")
    s = s.lstrip(b"\x00").rjust(expected_length, b"\x00")
    return r, s

@app.post("/sign/formats", response_model=SignFormatsResponse)
def sign_formats(req: SignRequest):
    if not isinstance(req.canonical, str) or req.canonical == "":
        raise HTTPException(status_code=400, detail="canonical debe ser string no vacío")

    key = load_private_key()
    data = req.canonical.encode("utf-8")
    alg, curve_name, hash_alg, rs_len = _detect_params(key)
    signature_der = key.sign(data, ec.ECDSA(hash_alg))

    r, s = _der_to_rs(signature_der, rs_len)
    rs = r + s

    return {
        "alg": alg,
        "curve": curve_name,
        "signature_der_base64": base64.b64encode(signature_der).decode(),
        "signature_p1363_base64": base64.b64encode(rs).decode(),
        "signature_p1363_base64url": base64.urlsafe_b64encode(rs).rstrip(b"=").decode(),
        "signed_bytes_base64": base64.b64encode(data).decode(),
    }


@app.post("/sign/jose", response_model=SignJoseResponse)
def sign_jose(req: SignRequest):
    if not isinstance(req.canonical, str) or req.canonical == "":
        raise HTTPException(status_code=400, detail="canonical debe ser string no vacío")

    key = load_private_key()
    data = req.canonical.encode("utf-8")
    alg, curve_name, hash_alg, rs_len = _detect_params(key)
    signature_der = key.sign(data, ec.ECDSA(hash_alg))
    r, s = _der_to_rs(signature_der, rs_len)
    rs = r + s

    return {
        "alg": alg,
        "curve": curve_name,
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

    key = load_private_key()
    alg, curve_name, hash_alg, rs_len = _detect_params(key)
    expected_len = 32 if alg == "ES256" else 48
    if len(digest) != expected_len:
        raise HTTPException(
            status_code=400,
            detail=f"digest debe tener {expected_len} bytes para {alg}",
        )

    # Sign prehashed digest explicitly using Prehashed de hash_alg correspondiente
    signature_der = key.sign(digest, ec.ECDSA(utils.Prehashed(hash_alg)))
    r, s = _der_to_rs(signature_der, rs_len)
    rs = r + s

    return {
        "alg": alg,
        "curve": curve_name,
        "digest_base64": base64.b64encode(digest).decode(),
        "signature_der_base64": base64.b64encode(signature_der).decode(),
        "signature_p1363_base64": base64.b64encode(rs).decode(),
        "signature_p1363_base64url": base64.urlsafe_b64encode(rs).rstrip(b"=").decode(),
    }
