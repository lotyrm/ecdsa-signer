# ECDSA Signer (FastAPI)

Un endpoint mínimo para firmar tu cadena canónica con ECDSA P-256 + SHA-256 (ES256) y devolver la firma en DER Base64 y formatos P1363.
Incluye utilidades para generar la cadena canónica desde JSON.

## Endpoints
- `GET /` → health check → `{"status":"ok"}`
- `POST /sign` → firma una cadena canónica (string)
  - body: `{"canonical": "<tu cadena>"}`
  - devuelve: `{"alg":"ES256","curve":"secp256r1","signature_der_base64":"...","signed_bytes_base64":"..."}`
- `POST /sign/formats` → firma cadena y devuelve DER y P1363/Base64/Base64URL
  - body: `{"canonical": "<tu cadena>"}`
  - devuelve: `signature_der_base64`, `signature_p1363_base64`, `signature_p1363_base64url`
- `POST /canonicalize` → genera la cadena canónica de un JSON
  - body: `{"json": <objeto JSON>}`
  - devuelve: `{"canonical": "<string canónico>"}`
- `POST /sign/json` → canoniza un JSON y luego firma la cadena resultante
  - body: `{"json": <objeto JSON>}`
  - devuelve: `{"alg":"ES256","curve":"secp256r1","canonical":"...","signature_der_base64":"...","signature_p1363_base64":"...","signature_p1363_base64url":"...","signed_bytes_base64":"..."}`

## Variables de Entorno
- `PRIVATE_KEY_PEM` → pega tu llave privada PKCS#8 completa (incluyendo `-----BEGIN PRIVATE KEY-----`).

## Ejecución Local
```bash
pip install -r requirements.txt
export PRIVATE_KEY_PEM="$(cat /ruta/a/private_key.pem)"
uvicorn app:app --host 0.0.0.0 --port 8000
```

También puedes ejecutar directamente con Python (respetando `PORT` si existe):

```bash
export PORT=8000  # o el que defina tu plataforma
python app.py
```

## Troubleshooting 504 (CloudFront / origin)
- Asegúrate que el proceso escucha en `0.0.0.0` y el puerto indicado por `PORT`.
- Verifica que la variable `PRIVATE_KEY_PEM` esté establecida; de lo contrario, el arranque falla.
- Revisa logs del origin (p. ej., Render/Heroku) para timeouts/errores de arranque.

## Notas sobre canónica JSON
- Llaves ordenadas (`sort_keys=True`) y separadores compactos (`separators=(",", ":")`).
- Unicode no se escapa (`ensure_ascii=False`).
- Números flotantes equivalentes a enteros se normalizan a enteros (por ejemplo, `1.0` → `1`). No es una implementación JCS completa, pero reduce variaciones comunes.
