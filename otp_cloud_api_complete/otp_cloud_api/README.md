# OTP Cloud API — Flask + Twilio Verify

A starter REST API for legitimate, user-requested SMS verification. Customers authenticate with individual API keys. Twilio Verify manages OTP generation, delivery and expiry.

## Features

- `POST /v1/otp/send` — request a verification SMS
- `POST /v1/otp/verify` — verify the submitted code
- Individual customer API keys; only a hash is stored in the database
- Per-IP endpoint limits and per-customer/per-phone send limits
- Phone number validation, masked/log-free raw phone handling in event logs
- SQLite for local use; PostgreSQL and Redis configuration supported for deployment
- Simple premium API landing page at `/`
- Health check at `/health`
- CLI commands to create, list and disable customer API keys

## Security and responsible use

Only send verification messages to people who requested them. Do not use this service for unsolicited bulk messaging, harassment, or account takeover. Never publish an API key or Twilio token in client-side JavaScript, source control, screenshots, or chat. Rotate credentials if exposed. Set spending limits and country permissions in Twilio. Before public launch, add customer identity checks, billing/quota enforcement, alerting, retention policies and operational monitoring.

This is a starter project, not a fully audited enterprise system. `memory://` rate limiting is for local testing only; configure Redis before deploying multiple workers or instances.

## 1. Local setup (Windows PowerShell)

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

Edit `.env` and provide your own:
- `SECRET_KEY` — generate with `py -c "import secrets; print(secrets.token_urlsafe(48))"`
- `TWILIO_ACCOUNT_SID`
- `TWILIO_AUTH_TOKEN` — use a rotated token if it was exposed
- `TWILIO_VERIFY_SERVICE_SID` — create a Verify Service in Twilio Console
- `DATABASE_URL` and `RATELIMIT_STORAGE_URI`

Do not put the credential values in `app.py`.

## 2. Initialize and run

```powershell
flask --app app init-db
py app.py
```

Open `http://127.0.0.1:5000`. Health check: `http://127.0.0.1:5000/health`.

## 3. Create a customer API key

After the app and dependencies are set up, run:

```powershell
flask --app app create-api-key "Demo Customer"
```

The full API key is printed once. Save it securely. If lost, disable the old client and create a new key. List clients without revealing keys:

```powershell
flask --app app list-api-clients
flask --app app disable-api-client 1
```

## 4. Test the API

Replace `YOUR_API_KEY` and use a phone number you own or are authorized to verify.

### Send OTP

```powershell
$headers = @{
  Authorization = "Bearer YOUR_API_KEY"
  "Content-Type" = "application/json"
}
$body = @{ phone = "+8801XXXXXXXXX" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:5000/v1/otp/send" -Headers $headers -Body $body
```

### Verify OTP

```powershell
$body = @{ phone = "+8801XXXXXXXXX"; code = "123456" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:5000/v1/otp/verify" -Headers $headers -Body $body
```

Use the actual code received by SMS; `123456` is only an example.

## 5. Online 24/7 deployment

Use a Python host that supports web services (for example Render, Railway, or a VPS). Add environment variables in the host dashboard, not in Git. Set the start command to:

```bash
gunicorn --workers 2 --bind 0.0.0.0:$PORT app:app
```

Before production:
1. Set `DATABASE_URL` to a managed PostgreSQL URL.
2. Set `RATELIMIT_STORAGE_URI` to your managed Redis URL.
3. Set `SECRET_KEY` and all Twilio values in the hosting provider's secret/environment settings.
4. Require HTTPS and configure custom domain.
5. Set Twilio spending limits and permitted destination countries.
6. Add durable client quotas/billing, monitoring, backups and abuse response.
7. Never deploy with debug mode enabled.

SQLite may be ephemeral on some cloud hosts; use PostgreSQL for durable production data.

## API reference

### `POST /v1/otp/send`

Headers:
`Authorization: Bearer YOUR_API_KEY`
`Content-Type: application/json`

Body:
```json
{"phone":"+8801XXXXXXXXX"}
```

Success:
```json
{"success":true,"message":"OTP request submitted.","status":"pending"}
```

### `POST /v1/otp/verify`

Body:
```json
{"phone":"+8801XXXXXXXXX","code":"ACTUAL_CODE"}
```

Success:
```json
{"success":true,"verified":true,"message":"Phone number verified."}
```

Typical errors: `400` invalid phone/code, `401` missing/invalid API key, `429` rate limit/quota, `502` provider send error.

## Important limitations

- Customer API keys are created using the CLI; there is no public signup or web admin dashboard in this starter.
- `CLIENT_LIFETIME_SEND_LIMIT` is stored as a counter on the customer record and is not a paid quota/billing system.
- For robust concurrent production traffic, use Redis rate limiting, database migrations, monitoring, and tested abuse controls.
