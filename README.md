# ECDSA Signer (FastAPI)

Un endpoint mínimo para firmar tu **cadena canónica** con **ECDSA P-384 + SHA-256** y devolver la firma en **DER Base64**.  
Úsalo desde Zapier para generar `x-signature` en llamadas a Círculo de Crédito.

## Endpoints
- `GET /` → health check → `{"status":"ok"}`
- `POST /sign` → body: `{"canonical": "<tu cadena>"}` → devuelve: `{"signature_der_base64": "..."}`

## Variables de Entorno
- `PRIVATE_KEY_PEM` → pega tu llave privada PKCS#8 completa (incluyendo `-----BEGIN PRIVATE KEY-----`).

## Ejecución Local
```bash
pip install -r requirements.txt
export PRIVATE_KEY_PEM="$(cat /ruta/a/private_key.pem)"
uvicorn app:app --host 0.0.0.0 --port 8000
