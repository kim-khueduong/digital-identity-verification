"""Shared PKI helpers for Round 5 (certificate-based key verification + replay protection).

Alice, Bob, Mallory, the CA script and the test runner all use these functions,
so the same verification logic is what gets attacked in every scenario.
"""
import os
import json
import time
import uuid
import datetime

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature

SHARED = os.path.abspath(os.path.dirname(__file__))
KEY_DIR = os.path.join(SHARED, "keys")
CA_DIR = os.path.join(SHARED, "ca")          # CA private key lives here (Mallory must NOT read it)
TRUST_DIR = os.path.join(SHARED, "trust")    # Bob's trust anchor + revocation list
PACKET_PATH = os.path.join(SHARED, "packet.json")
ALICE_PRIV = os.path.join(KEY_DIR, "alice_private.pem")
ALICE_PUB = os.path.join(KEY_DIR, "alice_public.pem")
ALICE_CERT = os.path.join(KEY_DIR, "alice_cert.pem")
CA_PRIV = os.path.join(CA_DIR, "ca_private.pem")
CA_CERT = os.path.join(TRUST_DIR, "ca_cert.pem")
REVOKED = os.path.join(TRUST_DIR, "revoked_serials.txt")

CA_NAME = "UTS Project Root CA"
MAX_AGE_SECONDS = 60


# ---------- small helpers ----------
def utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cn(name):
    return name.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value


def _not_before(cert):
    return getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)


def _not_after(cert):
    return getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)


def pss():
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)


def gen_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def save_private_key(key, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))


def save_public_key(key, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(key.public_key().public_bytes(serialization.Encoding.PEM,
                                              serialization.PublicFormat.SubjectPublicKeyInfo))


def load_private_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def save_cert(cert, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def load_cert(path):
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def cert_to_pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def ensure_alice_keys():
    """Reuse the Round 4 keypair if it exists, otherwise create it."""
    if not os.path.exists(ALICE_PRIV):
        key = gen_key()
        save_private_key(key, ALICE_PRIV)
        save_public_key(key, ALICE_PUB)
        return key, True
    return load_private_key(ALICE_PRIV), False


# ---------- certificate authority ----------
def make_ca(cn=CA_NAME, days=365):
    """Create a self-signed root CA. Returns (private_key, certificate)."""
    key = gen_key()
    cert = (x509.CertificateBuilder()
            .subject_name(_name(cn)).issuer_name(_name(cn))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(utcnow() - datetime.timedelta(minutes=1))
            .not_valid_after(utcnow() + datetime.timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(key, hashes.SHA256()))
    return key, cert


def issue_cert(ca_key, ca_cert, subject_cn, public_key, valid_from=None, valid_to=None):
    """CA signs a certificate binding subject_cn to public_key."""
    valid_from = valid_from or utcnow() - datetime.timedelta(minutes=1)
    valid_to = valid_to or utcnow() + datetime.timedelta(days=30)
    return (x509.CertificateBuilder()
            .subject_name(_name(subject_cn)).issuer_name(ca_cert.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(valid_from).not_valid_after(valid_to)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA256()))


def self_signed_cert(key, subject_cn):
    """A certificate the key owner signed for themselves (no CA involved)."""
    return (x509.CertificateBuilder()
            .subject_name(_name(subject_cn)).issuer_name(_name(subject_cn))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(utcnow() - datetime.timedelta(minutes=1))
            .not_valid_after(utcnow() + datetime.timedelta(days=30))
            .sign(key, hashes.SHA256()))


def load_revoked():
    if not os.path.exists(REVOKED):
        return set()
    with open(REVOKED) as f:
        return {int(line.strip()) for line in f if line.strip()}


# ---------- signed packets (message + nonce + timestamp) ----------
def canonical(message, nonce, timestamp):
    """Exact bytes that get signed. Nonce and timestamp are inside the signature,
    so an attacker cannot change them without invalidating it."""
    return json.dumps({"message": message, "nonce": nonce, "timestamp": timestamp},
                      sort_keys=True, separators=(",", ":")).encode()


def build_packet(message, private_key, cert, nonce=None, timestamp=None):
    nonce = nonce or uuid.uuid4().hex
    timestamp = int(time.time()) if timestamp is None else timestamp
    sig = private_key.sign(canonical(message, nonce, timestamp), pss(), hashes.SHA256())
    return {"message": message, "nonce": nonce, "timestamp": timestamp,
            "signature": sig.hex(), "cert_pem": cert_to_pem(cert)}


def write_packet(packet, path=PACKET_PATH):
    with open(path, "w") as f:
        json.dump(packet, f, indent=2)


def read_packet(path=PACKET_PATH):
    with open(path) as f:
        return json.load(f)


# ---------- Bob's verification ----------
def verify_packet(packet, trusted_ca_cert, seen_nonces, expected_cn="Alice",
                  revoked=frozenset(), max_age=MAX_AGE_SECONDS, now_ts=None):
    """Returns (accepted: bool, reason: str). Checks run in order:
    1 cert issued by trusted CA, 2 cert validity, 3 revocation, 4 identity,
    5 message signature, 6 timestamp freshness, 7 nonce not seen before."""
    now_ts = int(time.time()) if now_ts is None else now_ts
    try:
        cert = x509.load_pem_x509_certificate(packet["cert_pem"].encode())
    except Exception:
        return False, "malformed certificate"

    # 1. Key verification: was this certificate signed by the CA Bob trusts?
    if cert.issuer != trusted_ca_cert.subject:
        return False, "certificate issuer is not the trusted CA"
    try:
        trusted_ca_cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes,
                                            padding.PKCS1v15(), cert.signature_hash_algorithm)
    except InvalidSignature:
        return False, "certificate signature invalid (not signed by the trusted CA)"

    # 2. Validity window
    t = datetime.datetime.fromtimestamp(now_ts, datetime.timezone.utc)
    if not (_not_before(cert) <= t <= _not_after(cert)):
        return False, "certificate expired or not yet valid"

    # 3. Revocation
    if cert.serial_number in revoked:
        return False, "certificate has been revoked"

    # 4. Identity binding
    if _cn(cert.subject) != expected_cn:
        return False, f"certificate belongs to '{_cn(cert.subject)}', not '{expected_cn}'"

    # 5. Message signature using the now-trusted public key
    try:
        cert.public_key().verify(bytes.fromhex(packet["signature"]),
                                 canonical(packet["message"], packet["nonce"], packet["timestamp"]),
                                 pss(), hashes.SHA256())
    except (InvalidSignature, ValueError):
        return False, "message signature invalid"

    # 6. Freshness
    if abs(now_ts - packet["timestamp"]) > max_age:
        return False, "timestamp outside allowed window (stale or replayed)"

    # 7. Replay
    if packet["nonce"] in seen_nonces:
        return False, "nonce already used (replay detected)"

    return True, "accepted"
