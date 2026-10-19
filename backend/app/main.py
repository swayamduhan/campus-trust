from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from base64 import b64decode
from hashlib import sha256

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session, joinedload
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from . import blockchain, pki
from .database import AuditEvent, Base, Certificate, Enrollment, SessionLocal, engine, now_utc


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    pki.ensure_authorities()
    yield


app = FastAPI(title="CampusTrust API", description="University PKI and local EVM classroom demo.", version="1.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class EnrollmentCreate(BaseModel):
    full_name: str = Field(min_length=2, max_length=140)
    email: str = Field(min_length=5, max_length=254)
    university_id: str = Field(min_length=3, max_length=40, pattern=r"^[A-Za-z0-9._/-]+$")
    role: str = Field(pattern=r"^(student|faculty|staff)$")


class FingerprintRequest(BaseModel):
    fingerprint: str = Field(min_length=64, max_length=66, description="SHA-256 fingerprint in hex")


class SignatureVerifyRequest(BaseModel):
    certificate_id: int
    message: str = Field(min_length=1, max_length=5000)
    signature_base64: str = Field(min_length=16, max_length=12000)


def _iso(value):
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _certificate_out(cert: Certificate | None) -> dict | None:
    if cert is None:
        return None
    return {"id": cert.id, "enrollment_id": cert.enrollment_id, "serial_number": cert.serial_number, "fingerprint": cert.fingerprint, "status": cert.status, "chain_status": cert.chain_status, "chain_tx": cert.chain_tx, "issued_at": _iso(cert.issued_at), "revoked_at": _iso(cert.revoked_at)}


def _enrollment_out(row: Enrollment) -> dict:
    return {"id": row.id, "full_name": row.full_name, "email": row.email, "university_id": row.university_id, "role": row.role, "status": row.status, "created_at": _iso(row.created_at), "certificate": _certificate_out(row.certificate)}


def _audit(db: Session, event_type: str, subject: str, details: str = "") -> None:
    db.add(AuditEvent(event_type=event_type, subject=subject, details=details))


def _anchor(cert: Certificate) -> None:
    try:
        result = blockchain.anchor(cert.fingerprint)
        cert.chain_status = "anchored"
        cert.chain_tx = result["transaction_hash"]
    except Exception:
        cert.chain_status = "pending"


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "CampusTrust API"}


@app.get("/api/overview")
def overview(db: Session = Depends(get_db)) -> dict:
    count = lambda model, state: db.scalar(select(func.count()).select_from(model).where(model.status == state)) or 0
    return {"environment": "DEMO", "active_certificates": count(Certificate, "active"), "revoked_certificates": count(Certificate, "revoked"), "pending_requests": count(Enrollment, "pending"), "certificate_authorities": 2}


@app.get("/api/authorities")
def authorities() -> dict:
    pki.ensure_authorities()
    return pki.authority_summary()


@app.get("/api/blockchain/status")
def blockchain_status() -> dict:
    return blockchain.status()


@app.get("/api/ocsp/{fingerprint}")
def certificate_status(fingerprint: str, db: Session = Depends(get_db)) -> dict:
    normalized = fingerprint.lower().removeprefix("0x")
    if len(normalized) != 64 or any(char not in "0123456789abcdef" for char in normalized):
        raise HTTPException(status_code=422, detail="Fingerprint must be a 32-byte SHA-256 hex value")
    cert = db.scalar(select(Certificate).where(Certificate.fingerprint == normalized))
    local_state = "unknown" if cert is None else cert.status
    chain_state = "unavailable"
    try:
        record = blockchain.lookup(normalized)
        chain_state = "unknown" if not record["exists"] else ("revoked" if record["revoked"] else "good")
    except Exception:
        pass
    state = "revoked" if local_state == "revoked" or chain_state == "revoked" else "good" if local_state == "active" or chain_state == "good" else "unknown"
    return {"fingerprint": normalized, "certificate_status": state, "local_status": local_state, "chain_status": chain_state, "checked_at": _iso(now_utc()), "responder": "CampusTrust demo status service"}


@app.get("/api/crl.pem")
def certificate_revocation_list(db: Session = Depends(get_db)) -> Response:
    issuing_cert = x509.load_pem_x509_certificate(pki.ISSUING_CERT.read_bytes())
    issuing_key = serialization.load_pem_private_key(pki.ISSUING_KEY.read_bytes(), password=None)
    now = datetime.now(timezone.utc)
    builder = x509.CertificateRevocationListBuilder().issuer_name(issuing_cert.subject).last_update(now - timedelta(minutes=1)).next_update(now + timedelta(days=1))
    revoked = db.scalars(select(Certificate).where(Certificate.status == "revoked")).all()
    for cert in revoked:
        revocation_time = cert.revoked_at or now
        if revocation_time.tzinfo is None:
            revocation_time = revocation_time.replace(tzinfo=timezone.utc)
        entry = x509.RevokedCertificateBuilder().serial_number(int(cert.serial_number, 16)).revocation_date(revocation_time).build()
        builder = builder.add_revoked_certificate(entry)
    crl_pem = builder.sign(issuing_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)
    return Response(content=crl_pem, media_type="application/pkix-crl", headers={"Content-Disposition": "attachment; filename=campustrust-revoked.crl.pem"})


@app.get("/api/enrollments")
def list_enrollments(status: str | None = None, db: Session = Depends(get_db)) -> list[dict]:
    query = select(Enrollment).options(joinedload(Enrollment.certificate)).order_by(desc(Enrollment.id))
    if status in {"pending", "approved", "rejected"}:
        query = query.where(Enrollment.status == status)
    return [_enrollment_out(row) for row in db.scalars(query).unique().all()]


@app.post("/api/enrollments", status_code=201)
def create_enrollment(body: EnrollmentCreate, db: Session = Depends(get_db)) -> dict:
    email = body.email.strip().lower()
    if "@" not in email or email.startswith("@") or email.endswith("@"):
        raise HTTPException(status_code=422, detail="Enter a valid email address")
    university_id = body.university_id.strip().upper()
    exists = db.scalar(select(Enrollment).where((Enrollment.email == email) | (Enrollment.university_id == university_id)))
    if exists:
        raise HTTPException(status_code=409, detail="An enrollment already uses this email or university ID")
    row = Enrollment(full_name=body.full_name.strip(), email=email, university_id=university_id, role=body.role)
    db.add(row)
    db.flush()
    _audit(db, "enrollment.submitted", f"{row.full_name} ({row.university_id})", row.role)
    db.commit()
    db.refresh(row)
    return _enrollment_out(row)


@app.post("/api/enrollments/{enrollment_id}/approve")
def approve_enrollment(enrollment_id: int, db: Session = Depends(get_db)) -> dict:
    row = db.scalar(select(Enrollment).options(joinedload(Enrollment.certificate)).where(Enrollment.id == enrollment_id))
    if row is None:
        raise HTTPException(status_code=404, detail="Enrollment not found")
    if row.status != "pending":
        raise HTTPException(status_code=409, detail=f"Enrollment is already {row.status}")
    cert_pem, private_key_pem, fingerprint, serial_number = pki.issue_user_certificate(row.full_name, row.email, row.university_id, row.role)
    cert = Certificate(enrollment_id=row.id, serial_number=serial_number, fingerprint=fingerprint, certificate_pem=cert_pem)
    row.status = "approved"
    row.reviewed_at = now_utc()
    db.add(cert)
    db.flush()
    row.certificate = cert
    _anchor(cert)
    _audit(db, "certificate.issued", f"{row.full_name} ({row.university_id})", f"serial={serial_number}; chain={cert.chain_status}")
    db.commit()
    db.refresh(cert)
    return {"enrollment": _enrollment_out(row), "certificate_pem": cert_pem, "private_key_pem": private_key_pem, "private_key_notice": "This private key is shown once and is not stored by CampusTrust. Save it securely now.", "chain_status": cert.chain_status, "chain_tx": cert.chain_tx}


@app.post("/api/enrollments/{enrollment_id}/reject")
def reject_enrollment(enrollment_id: int, db: Session = Depends(get_db)) -> dict:
    row = db.get(Enrollment, enrollment_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Enrollment not found")
    if row.status != "pending":
        raise HTTPException(status_code=409, detail=f"Enrollment is already {row.status}")
    row.status = "rejected"
    row.reviewed_at = now_utc()
    _audit(db, "enrollment.rejected", f"{row.full_name} ({row.university_id})")
    db.commit()
    return {"id": row.id, "status": row.status}


@app.get("/api/certificates")
def list_certificates(status: str | None = None, db: Session = Depends(get_db)) -> list[dict]:
    query = select(Certificate).options(joinedload(Certificate.enrollment)).order_by(desc(Certificate.id))
    if status in {"active", "revoked"}:
        query = query.where(Certificate.status == status)
    result = []
    for cert in db.scalars(query).unique().all():
        result.append({**_certificate_out(cert), "full_name": cert.enrollment.full_name, "email": cert.enrollment.email, "university_id": cert.enrollment.university_id, "role": cert.enrollment.role})
    return result


@app.get("/api/certificates/{certificate_id}")
def get_certificate(certificate_id: int, db: Session = Depends(get_db)) -> dict:
    cert = db.scalar(select(Certificate).options(joinedload(Certificate.enrollment)).where(Certificate.id == certificate_id))
    if cert is None:
        raise HTTPException(status_code=404, detail="Certificate not found")
    try:
        chain_record = blockchain.lookup(cert.fingerprint)
    except Exception as exc:
        chain_record = {"exists": False, "detail": str(exc)}
    return {**_certificate_out(cert), "full_name": cert.enrollment.full_name, "email": cert.enrollment.email, "university_id": cert.enrollment.university_id, "role": cert.enrollment.role, "certificate_pem": cert.certificate_pem, "chain_record": chain_record}


@app.post("/api/certificates/{certificate_id}/anchor")
def anchor_certificate(certificate_id: int, db: Session = Depends(get_db)) -> dict:
    cert = db.get(Certificate, certificate_id)
    if cert is None:
        raise HTTPException(status_code=404, detail="Certificate not found")
    if cert.status == "revoked":
        raise HTTPException(status_code=409, detail="A revoked certificate cannot be anchored as active; use sync to publish its revocation")
    if cert.chain_status in {"anchored", "revoked on-chain"}:
        return {"chain_status": cert.chain_status, "transaction_hash": cert.chain_tx}
    try:
        result = blockchain.anchor(cert.fingerprint)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    cert.chain_status = "anchored"
    cert.chain_tx = result["transaction_hash"]
    _audit(db, "certificate.anchored", cert.fingerprint, cert.chain_tx)
    db.commit()
    return {"chain_status": cert.chain_status, "transaction_hash": cert.chain_tx}


@app.post("/api/certificates/{certificate_id}/sync")
def sync_certificate(certificate_id: int, db: Session = Depends(get_db)) -> dict:
    cert = db.get(Certificate, certificate_id)
    if cert is None:
        raise HTTPException(status_code=404, detail="Certificate not found")
    try:
        record = blockchain.lookup(cert.fingerprint)
        if cert.status == "revoked":
            if not record["exists"]:
                blockchain.anchor(cert.fingerprint)
                record = blockchain.lookup(cert.fingerprint)
            if not record["revoked"]:
                result = blockchain.revoke(cert.fingerprint)
                cert.chain_tx = result["transaction_hash"]
            cert.chain_status = "revoked on-chain"
        else:
            if not record["exists"]:
                result = blockchain.anchor(cert.fingerprint)
                cert.chain_tx = result["transaction_hash"]
            elif record["revoked"]:
                raise HTTPException(status_code=409, detail="The blockchain already records this certificate as revoked")
            cert.chain_status = "anchored"
        _audit(db, "certificate.synced", cert.fingerprint, cert.chain_status)
        db.commit()
        return {"status": cert.status, "chain_status": cert.chain_status, "transaction_hash": cert.chain_tx}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.post("/api/certificates/{certificate_id}/revoke")
def revoke_certificate(certificate_id: int, db: Session = Depends(get_db)) -> dict:
    cert = db.get(Certificate, certificate_id)
    if cert is None:
        raise HTTPException(status_code=404, detail="Certificate not found")
    if cert.status == "revoked":
        return {"status": cert.status, "chain_status": cert.chain_status, "transaction_hash": cert.chain_tx}
    try:
        record = blockchain.lookup(cert.fingerprint)
        if not record["exists"]:
            blockchain.anchor(cert.fingerprint)
            record = blockchain.lookup(cert.fingerprint)
        if not record["revoked"]:
            result = blockchain.revoke(cert.fingerprint)
            cert.chain_tx = result["transaction_hash"]
        cert.chain_status = "revoked on-chain"
    except blockchain.BlockchainNotConfigured:
        cert.chain_status = "revocation pending"
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"On-chain revocation failed; certificate remains active: {exc}") from exc
    cert.status = "revoked"
    cert.revoked_at = now_utc()
    _audit(db, "certificate.revoked", cert.fingerprint, f"chain={cert.chain_status}")
    db.commit()
    return {"status": cert.status, "chain_status": cert.chain_status, "transaction_hash": cert.chain_tx}


@app.get("/api/audit")
def audit_events(limit: int = 100, db: Session = Depends(get_db)) -> list[dict]:
    rows = db.scalars(select(AuditEvent).order_by(desc(AuditEvent.id)).limit(max(1, min(limit, 500)))).all()
    return [{"id": row.id, "event_type": row.event_type, "actor": row.actor, "subject": row.subject, "details": row.details, "created_at": _iso(row.created_at)} for row in rows]


@app.post("/api/signatures/verify")
def verify_signature(body: SignatureVerifyRequest, db: Session = Depends(get_db)) -> dict:
    cert = db.scalar(select(Certificate).options(joinedload(Certificate.enrollment)).where(Certificate.id == body.certificate_id))
    if cert is None:
        raise HTTPException(status_code=404, detail="Certificate not found")
    if cert.status != "active":
        raise HTTPException(status_code=409, detail="This certificate has been revoked")
    try:
        end_entity = x509.load_pem_x509_certificate(cert.certificate_pem.encode())
        intermediate = x509.load_pem_x509_certificate(pki.ISSUING_CERT.read_bytes())
        root = x509.load_pem_x509_certificate(pki.ROOT_CERT.read_bytes())
        if end_entity.issuer != intermediate.subject or intermediate.issuer != root.subject:
            raise HTTPException(status_code=422, detail="Certificate is not issued by this CampusTrust hierarchy")
        now = datetime.now(timezone.utc)
        if now < end_entity.not_valid_before_utc or now > end_entity.not_valid_after_utc:
            raise HTTPException(status_code=422, detail="Certificate is outside its validity period")
        root.public_key().verify(intermediate.signature, intermediate.tbs_certificate_bytes, padding.PKCS1v15(), intermediate.signature_hash_algorithm)
        intermediate.public_key().verify(end_entity.signature, end_entity.tbs_certificate_bytes, padding.PKCS1v15(), end_entity.signature_hash_algorithm)
        signature = b64decode(body.signature_base64, validate=True)
        public_key = end_entity.public_key()
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise HTTPException(status_code=422, detail="Unsupported certificate public key type")
        public_key.verify(signature, body.message.encode(), padding.PKCS1v15(), hashes.SHA256())
    except HTTPException:
        raise
    except InvalidSignature as exc:
        raise HTTPException(status_code=422, detail="Signature verification failed: the message or key does not match") from exc
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail="Invalid signature encoding") from exc

    content_hash = sha256(body.message.encode()).hexdigest()
    action_hash = sha256(signature).hexdigest()
    try:
        record = blockchain.lookup(cert.fingerprint)
        if record["revoked"]:
            raise HTTPException(status_code=409, detail="Blockchain registry marks this certificate revoked")
        anchored = blockchain.anchor_signed_action(cert.fingerprint, action_hash, content_hash)
        tx_hash = anchored["transaction_hash"]
        chain_status = "anchored"
    except HTTPException:
        raise
    except Exception:
        tx_hash = None
        chain_status = "pending"
    _audit(db, "signature.verified", f"{cert.enrollment.full_name} · {cert.fingerprint[:16]}", f"SHA-256={content_hash}; chain={chain_status}")
    db.commit()
    return {"valid": True, "certificate_id": cert.id, "signer": cert.enrollment.full_name, "content_hash": content_hash, "action_hash": action_hash, "chain_status": chain_status, "transaction_hash": tx_hash}


@app.post("/api/blockchain/certificates/anchor")
def anchor_fingerprint(body: FingerprintRequest) -> dict:
    try:
        return blockchain.anchor(body.fingerprint)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except blockchain.BlockchainNotConfigured as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.post("/api/blockchain/certificates/revoke")
def revoke_fingerprint(body: FingerprintRequest) -> dict:
    try:
        return blockchain.revoke(body.fingerprint)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except blockchain.BlockchainNotConfigured as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.get("/api/blockchain/certificates/{fingerprint}")
def lookup_fingerprint(fingerprint: str) -> dict:
    try:
        return blockchain.lookup(fingerprint)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except blockchain.BlockchainNotConfigured as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
