# ECDSA Signer (FastAPI)

Servicio para firmar tu cadena canónica con ECDSA y obtener la firma en formato JOSE (r||s) Base64URL sin `=` (P-1363), compatible con Círculo de Crédito. Auto‑detecta la curva según tu llave: ES256 (P‑256) o ES384 (P‑384).

## Endpoints
- `GET /` → health check → `{"status":"ok"}`
- `POST /sign` → body: `{"canonical": "<tu cadena>"}` → devuelve DER Base64 junto con metadatos
- `POST /sign/formats` → body: `{"canonical": "<tu cadena>"}` → devuelve DER, P‑1363 Base64 y P‑1363 Base64URL
- `POST /sign/jose` → body: `{"canonical": "<tu cadena>"}` → devuelve directamente `signature_p1363_base64url` (lo que va en `X-Signature`)

## Variables de Entorno
- `PRIVATE_KEY_PEM` → pega tu llave privada PKCS#8 completa (incluye `-----BEGIN PRIVATE KEY-----`).

## Ejecución Local
```bash
pip install -r requirements.txt
export PRIVATE_KEY_PEM="$(cat /ruta/a/private_key.pem)"
uvicorn app:app --host 0.0.0.0 --port 8000
```

## Uso en Zapier (POST a Círculo de Crédito)
- Body: en el campo JSON, inserta solo la variable del paso "Canonical Json" (tu JSON compacto exacto).
- Headers:
  - `Content-Type: application/json`
  - `X-Signature`: usa `signature_p1363_base64url` del paso que llama a `/sign/jose` o `/sign/formats`.

### Validaciones recomendadas
- La cadena enviada debe coincidir con `signed_bytes_base64` (al decodificar en UTF‑8).
- La firma debe ser Base64URL sin `=` y medir 86 (ES256) o 128 (ES384) caracteres aprox.
