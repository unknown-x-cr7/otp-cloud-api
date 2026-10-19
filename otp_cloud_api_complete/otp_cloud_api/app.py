import os
import hashlib
import hmac
import secrets
from datetime import datetime, timezone

import phonenumbers
from dotenv import load_dotenv
from flask import Flask, jsonify, request, render_template
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from twilio.base.exceptions import TwilioRestException
from twilio.rest import Client
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

def required_env(name):
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value

app = Flask(__name__)
app.config["SECRET_KEY"] = required_env("SECRET_KEY")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///otp_api.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
db = SQLAlchemy(app)

# Redis is strongly recommended for multi-worker production deployments.
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[],
    storage_uri=os.getenv("RATELIMIT_STORAGE_URI", "memory://"),
)

TWILIO_ACCOUNT_SID = required_env("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = required_env("TWILIO_AUTH_TOKEN")
TWILIO_VERIFY_SERVICE_SID = required_env("TWILIO_VERIFY_SERVICE_SID")
twilio = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)

def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

class ApiClient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    key_prefix = db.Column(db.String(18), unique=True, nullable=False, index=True)
    key_hash = db.Column(db.String(255), nullable=False)
    active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    requests_sent = db.Column(db.Integer, nullable=False, default=0)

class ApiEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey("api_client.id"), nullable=True, index=True)
    event = db.Column(db.String(40), nullable=False)
    phone_hash = db.Column(db.String(64), nullable=True, index=True)
    outcome = db.Column(db.String(30), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

def get_bearer_token():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    return auth[7:].strip()

def authenticate_client():
    token = get_bearer_token()
    if not token or len(token) < 32:
        return None
    prefix = token[:18]
    client = ApiClient.query.filter_by(key_prefix=prefix, active=True).first()
    if client and check_password_hash(client.key_hash, token):
        return client
    return None

def valid_phone(phone):
    try:
        parsed = phonenumbers.parse(phone, None)
        return phonenumbers.is_valid_number(parsed)
    except (phonenumbers.NumberParseException, TypeError):
        return False

def record_event(client_id, event, phone, outcome):
    db.session.add(ApiEvent(
        client_id=client_id,
        event=event,
        phone_hash=digest(phone) if phone else None,
        outcome=outcome
    ))
    db.session.commit()

@app.errorhandler(429)
def too_many_requests(_error):
    return jsonify(error="rate_limit_exceeded", message="Too many requests. Try again later."), 429

@app.errorhandler(413)
def payload_too_large(_error):
    return jsonify(error="payload_too_large"), 413

@app.get("/")
def index():
    return render_template("index.html")

@app.get("/health")
def health():
    return jsonify(status="ok")

@app.post("/v1/otp/send")
@limiter.limit("30 per minute")
def send_otp():
    client = authenticate_client()
    if not client:
        return jsonify(error="unauthorized", message="A valid API key is required."), 401

    data = request.get_json(silent=True) or {}
    phone = str(data.get("phone", "")).strip()
    if not valid_phone(phone):
        return jsonify(error="invalid_phone", message="Use a valid international phone number, e.g. +8801XXXXXXXXX."), 400

    # Per-client and per-recipient controls. These are deliberately conservative.
    if client.requests_sent >= int(os.getenv("CLIENT_LIFETIME_SEND_LIMIT", "1000")):
        return jsonify(error="client_quota_exceeded", message="This API key has reached its configured send limit."), 429

    recent = ApiEvent.query.filter(
        ApiEvent.client_id == client.id,
        ApiEvent.event == "send",
        ApiEvent.phone_hash == digest(phone),
        ApiEvent.created_at >= utcnow().replace(microsecond=0)  # overwritten below with a safe hour query
    ).count()
    # Query in the last hour without storing raw phone numbers.
    from datetime import timedelta
    recent = ApiEvent.query.filter(
        ApiEvent.client_id == client.id,
        ApiEvent.event == "send",
        ApiEvent.phone_hash == digest(phone),
        ApiEvent.created_at >= utcnow() - timedelta(hours=1)
    ).count()
    if recent >= int(os.getenv("PHONE_SENDS_PER_HOUR", "3")):
        return jsonify(error="recipient_rate_limit", message="Too many OTP requests for this number. Try again later."), 429

    try:
        verification = twilio.verify.v2.services(
            TWILIO_VERIFY_SERVICE_SID
        ).verifications.create(to=phone, channel="sms")
        client.requests_sent += 1
        db.session.commit()
        record_event(client.id, "send", phone, verification.status or "submitted")
        return jsonify(success=True, message="OTP request submitted.", status=verification.status), 200
    except TwilioRestException as exc:
        app.logger.warning("Twilio send failed; error code=%s", exc.code)
        record_event(client.id, "send", phone, "provider_error")
        return jsonify(error="provider_error", message="OTP provider could not process the request."), 502

@app.post("/v1/otp/verify")
@limiter.limit("10 per 10 minutes")
def verify_otp():
    client = authenticate_client()
    if not client:
        return jsonify(error="unauthorized", message="A valid API key is required."), 401

    data = request.get_json(silent=True) or {}
    phone = str(data.get("phone", "")).strip()
    code = str(data.get("code", "")).strip()

    if not valid_phone(phone):
        return jsonify(error="invalid_phone", message="Enter a valid international phone number."), 400
    if not code.isdigit() or not 4 <= len(code) <= 10:
        return jsonify(error="invalid_code", message="Enter the verification code received by SMS."), 400

    try:
        result = twilio.verify.v2.services(
            TWILIO_VERIFY_SERVICE_SID
        ).verification_checks.create(to=phone, code=code)
        approved = result.status == "approved"
        record_event(client.id, "verify", phone, "approved" if approved else "rejected")
        if approved:
            return jsonify(success=True, verified=True, message="Phone number verified."), 200
        return jsonify(success=False, verified=False, message="Incorrect or expired code."), 400
    except TwilioRestException as exc:
        app.logger.warning("Twilio verify failed; error code=%s", exc.code)
        record_event(client.id, "verify", phone, "provider_error")
        return jsonify(error="verification_error", message="Could not verify this code. It may be invalid or expired."), 400

# Admin endpoints are intentionally omitted from the public API.
# Create/manage customer API keys with the one-time CLI script instead.

@app.cli.command("init-db")
def init_db():
    """Create database tables."""
    db.create_all()
    print("Database tables created.")

@app.cli.command("create-api-key")
def create_api_key():
    """Create a customer key: flask --app app create-api-key 'Customer Name'."""
    import sys
    name = " ".join(sys.argv[2:]).strip()
    if not name:
        print("Usage: flask --app app create-api-key 'Customer Name'")
        raise SystemExit(2)
    raw_key = "otp_live_" + secrets.token_urlsafe(32)
    prefix = raw_key[:18]
    client = ApiClient(
        name=name[:100],
        key_prefix=prefix,
        key_hash=generate_password_hash(raw_key),
    )
    db.session.add(client)
    db.session.commit()
    print("\nCopy this API key now. It will not be shown again:\n")
    print(raw_key)
    print("\nStore it securely and send it only to the authorized customer.\n")

@app.cli.command("list-api-clients")
def list_api_clients():
    """List API clients without revealing API keys."""
    for client in ApiClient.query.order_by(ApiClient.id).all():
        print(f"id={client.id} name={client.name!r} active={client.active} sent={client.requests_sent} prefix={client.key_prefix}")

@app.cli.command("disable-api-client")
def disable_api_client():
    """Disable a client: flask --app app disable-api-client CLIENT_ID."""
    import sys
    if len(sys.argv) < 3 or not sys.argv[2].isdigit():
        print("Usage: flask --app app disable-api-client CLIENT_ID")
        raise SystemExit(2)
    client = db.session.get(ApiClient, int(sys.argv[2]))
    if not client:
        print("Client not found.")
        raise SystemExit(1)
    client.active = False
    db.session.commit()
    print("Client disabled.")

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    # For local development only. Use gunicorn in production.
    app.run(host="127.0.0.1", port=int(os.getenv("PORT", "5000")), debug=False)
