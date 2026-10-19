"""Small two-tier X.509 CA used by the classroom demo."""
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

PKI_DIR = Path(__file__).resolve().parents[1] / "data" / "pki"
ROOT_CERT = PKI_DIR / "root-ca.pem"
ROOT_KEY = PKI_DIR / "root-ca-key.pem"
ISSUING_CERT = PKI_DIR / "intermediate-ca.pem"
ISSUING_KEY = PKI_DIR / "intermediate-ca-key.pem"


def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


def _write_private_key(path: Path, key: rsa.RSAPrivateKey) -> None:
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    try:
        path.chmod(0o600)
    except OSError:
        pass


def ensure_authorities() -> dict[str, str]:
    PKI_DIR.mkdir(parents=True, exist_ok=True)
    if all(path.exists() for path in (ROOT_CERT, ROOT_KEY, ISSUING_CERT, ISSUING_KEY)):
        return authority_summary()

    now = datetime.now(timezone.utc)
    root_key = _key()
    root_name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Northbridge University"), x509.NameAttribute(NameOID.COMMON_NAME, "Northbridge University Root CA")])
    root_cert = (
        x509.CertificateBuilder().subject_name(root_name).issuer_name(root_name).public_key(root_key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=None, decipher_only=None), critical=True)
        .sign(root_key, hashes.SHA256())
    )
    issuing_key = _key()
    issuing_name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Northbridge University"), x509.NameAttribute(NameOID.COMMON_NAME, "Northbridge University Issuing CA")])
    issuing_cert = (
        x509.CertificateBuilder().subject_name(issuing_name).issuer_name(root_cert.subject).public_key(issuing_key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1825))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=None, decipher_only=None), critical=True)
        .sign(root_key, hashes.SHA256())
    )
    _write_private_key(ROOT_KEY, root_key)
    ROOT_CERT.write_bytes(root_cert.public_bytes(serialization.Encoding.PEM))
    _write_private_key(ISSUING_KEY, issuing_key)
    ISSUING_CERT.write_bytes(issuing_cert.public_bytes(serialization.Encoding.PEM))
    return authority_summary()


def authority_summary() -> dict[str, str]:
    return {
        "root_subject": x509.load_pem_x509_certificate(ROOT_CERT.read_bytes()).subject.rfc4514_string(),
        "intermediate_subject": x509.load_pem_x509_certificate(ISSUING_CERT.read_bytes()).subject.rfc4514_string(),
        "root_fingerprint": x509.load_pem_x509_certificate(ROOT_CERT.read_bytes()).fingerprint(hashes.SHA256()).hex(),
        "intermediate_fingerprint": x509.load_pem_x509_certificate(ISSUING_CERT.read_bytes()).fingerprint(hashes.SHA256()).hex(),
    }


def issue_user_certificate(full_name: str, email: str, university_id: str, role: str) -> tuple[str, str, str, str]:
    intermediate = x509.load_pem_x509_certificate(ISSUING_CERT.read_bytes())
    issuer_key = serialization.load_pem_private_key(ISSUING_KEY.read_bytes(), password=None)
    user_key = _key()
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Northbridge University"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, role.title()),
        x509.NameAttribute(NameOID.COMMON_NAME, full_name),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
        x509.NameAttribute(NameOID.USER_ID, university_id),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(subject).issuer_name(intermediate.subject).public_key(user_key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=True, key_encipherment=True, data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=None, decipher_only=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH, x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION]), critical=False)
        .add_extension(x509.SubjectAlternativeName([x509.RFC822Name(email)]), critical=False)
        .sign(issuer_key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = user_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    serial = format(cert.serial_number, "x")
    return cert_pem, key_pem, fingerprint, serial
