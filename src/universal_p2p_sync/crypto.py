"""Cryptographic building blocks.

Everything here composes standard primitives from the ``cryptography``
package; no primitive is implemented by hand.

* **Device identity**: an Ed25519 key pair. The device ID is the hex SHA-256
  of the raw public key, so it cannot be claimed without the private key.
* **Key agreement**: a separate X25519 key pair per device, used to deliver
  group keys to members ("sealed boxes": ephemeral X25519 + HKDF-SHA256 +
  ChaCha20-Poly1305, the same construction as ECIES/HPKE base mode).
* **TLS**: a self-signed X.509 certificate over the Ed25519 identity key.
* **Payload encryption**: ChaCha20-Poly1305 with a random 96-bit nonce.
* **Signatures**: Ed25519 over canonical JSON (sorted keys, no whitespace).
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import json
import logging
import os
import secrets
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import NameOID

from .errors import ConfigurationError, IdentityError

log = logging.getLogger(__name__)

KEY_SIZE = 32
NONCE_SIZE = 12
PAIRING_CODE_DIGITS = 6

_RAW = serialization.Encoding.Raw
_RAW_PUB = serialization.PublicFormat.Raw


# ---------------------------------------------------------------- encoding helpers


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64d(text: str, *, expected_len: int | None = None) -> bytes:
    """Decode unpadded URL-safe base64; raises ValueError on bad input."""
    if not isinstance(text, str) or len(text) > 1 << 22:
        raise ValueError("expected a base64 string")
    try:
        data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError) as exc:
        raise ValueError("invalid base64") from exc
    if b64e(data) != text:
        raise ValueError("non-canonical base64")
    if expected_len is not None and len(data) != expected_len:
        raise ValueError(f"expected {expected_len} bytes, got {len(data)}")
    return data


def canonical_json(value: Any) -> bytes:
    """Deterministic JSON encoding used for everything that is hashed or signed."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def device_id_for(public_key: bytes) -> str:
    """The device ID: hex SHA-256 of the raw 32-byte Ed25519 public key."""
    return sha256_hex(public_key)


def format_fingerprint(device_id: str) -> str:
    """Human-comparable fingerprint: the first 160 bits of the device ID."""
    head = device_id[:40].upper()
    return " ".join(head[i : i + 4] for i in range(0, len(head), 4))


def random_id(nbytes: int = 16) -> str:
    return secrets.token_hex(nbytes)


def constant_time_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


# ---------------------------------------------------------------- signatures


def verify_signature(public_key: bytes, signature: bytes, message: bytes) -> bool:
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False


def public_key_from_cert(der: bytes) -> bytes:
    """Extract the raw Ed25519 public key from a DER certificate."""
    cert = x509.load_der_x509_certificate(der)
    key = cert.public_key()
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise IdentityError("peer certificate does not carry an Ed25519 key")
    return key.public_bytes(_RAW, _RAW_PUB)


# ---------------------------------------------------------------- symmetric encryption


def new_symmetric_key() -> bytes:
    return ChaCha20Poly1305.generate_key()


def encrypt(key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(NONCE_SIZE)
    return nonce, ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise IdentityError("decryption failed (wrong key or tampered data)") from exc


def _seal_key(shared: bytes, epk: bytes, rpk: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=KEY_SIZE, salt=None, info=b"up2p-seal-v1" + epk + rpk
    ).derive(shared)


def seal(recipient_public: bytes, plaintext: bytes, aad: bytes = b"") -> dict[str, str]:
    """Encrypt ``plaintext`` so only the holder of the X25519 private key can read it."""
    eph = x25519.X25519PrivateKey.generate()
    epk = eph.public_key().public_bytes(_RAW, _RAW_PUB)
    shared = eph.exchange(x25519.X25519PublicKey.from_public_bytes(recipient_public))
    nonce, ct = encrypt(_seal_key(shared, epk, recipient_public), plaintext, aad)
    return {"epk": b64e(epk), "n": b64e(nonce), "ct": b64e(ct)}


def pairing_code(
    app_id: str,
    initiator_key: bytes,
    responder_key: bytes,
    initiator_nonce: bytes,
    responder_nonce: bytes,
) -> str:
    """Short authentication string both users compare during pairing."""
    digest = hashlib.sha256(
        b"up2p-pair-v1\x00"
        + app_id.encode()
        + b"\x00"
        + initiator_key
        + responder_key
        + initiator_nonce
        + responder_nonce
    ).digest()
    value = int.from_bytes(digest[:8], "big") % (10**PAIRING_CODE_DIGITS)
    return f"{value:0{PAIRING_CODE_DIGITS}d}"


# ---------------------------------------------------------------- device identity


def default_data_dir() -> Path:
    """Per-user directory for device keys (not shared between OS users)."""
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "universal-p2p-sync"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "universal-p2p-sync"
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "universal-p2p-sync"


def _write_private(path: Path, data: bytes) -> None:
    """Create ``path`` with owner-only permissions (0600 on POSIX)."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0)
    fd = os.open(tmp, flags, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)


@dataclass(frozen=True)
class DeviceIdentity:
    """A device's long-term keys, loaded from (or created in) ``directory``."""

    directory: Path
    signing_key: ed25519.Ed25519PrivateKey
    exchange_key: x25519.X25519PrivateKey
    cert_path: Path
    key_path: Path
    passphrase: bytes | None

    @property
    def public_key(self) -> bytes:
        return self.signing_key.public_key().public_bytes(_RAW, _RAW_PUB)

    @property
    def exchange_public_key(self) -> bytes:
        return self.exchange_key.public_key().public_bytes(_RAW, _RAW_PUB)

    @property
    def device_id(self) -> str:
        return device_id_for(self.public_key)

    @property
    def fingerprint(self) -> str:
        return format_fingerprint(self.device_id)

    def sign(self, message: bytes) -> bytes:
        return self.signing_key.sign(message)

    def open_sealed(self, box: dict[str, Any], aad: bytes = b"") -> bytes:
        try:
            epk = b64d(box["epk"], expected_len=32)
            nonce = b64d(box["n"], expected_len=NONCE_SIZE)
            ct = b64d(box["ct"])
        except (KeyError, TypeError, ValueError) as exc:
            raise IdentityError("malformed sealed box") from exc
        shared = self.exchange_key.exchange(x25519.X25519PublicKey.from_public_bytes(epk))
        key = _seal_key(shared, epk, self.exchange_public_key)
        return decrypt(key, nonce, ct, aad)

    @classmethod
    def load_or_create(cls, directory: Path, passphrase: str | None = None) -> DeviceIdentity:
        """Load the identity in ``directory``, generating it on first use.

        Private keys are PKCS#8 PEM files readable only by the current user
        (POSIX mode 0600; on Windows the per-user profile ACL applies). When a
        passphrase is given they are encrypted with it.
        """
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        secret = passphrase.encode() if passphrase else None
        key_path = directory / "device_ed25519.pem"
        xkey_path = directory / "device_x25519.pem"
        cert_path = directory / "device_cert.pem"

        signing = cls._load_or_generate(key_path, secret, ed25519.Ed25519PrivateKey)
        exchange = cls._load_or_generate(xkey_path, secret, x25519.X25519PrivateKey)
        identity = cls(directory, signing, exchange, cert_path, key_path, secret)
        identity._ensure_certificate()
        return identity

    @staticmethod
    def _load_or_generate(path: Path, secret: bytes | None, key_type: Any) -> Any:
        if path.exists():
            if sys.platform != "win32" and path.stat().st_mode & 0o077:
                log.warning("private key %s is accessible by other users; fixing mode", path)
                os.chmod(path, 0o600)
            try:
                key = serialization.load_pem_private_key(path.read_bytes(), password=secret)
            except (ValueError, TypeError) as exc:
                raise IdentityError(
                    f"cannot load {path}: wrong passphrase or corrupted key file"
                ) from exc
            if not isinstance(key, key_type):
                raise IdentityError(f"{path} does not contain the expected key type")
            return key
        key = key_type.generate()
        encryption = (
            serialization.BestAvailableEncryption(secret)
            if secret
            else serialization.NoEncryption()
        )
        pem = key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption
        )
        _write_private(path, pem)
        log.info("generated new device key %s", path)
        return key

    def _ensure_certificate(self) -> None:
        """(Re)create the self-signed TLS certificate for the identity key."""
        if self.cert_path.exists():
            try:
                cert = x509.load_pem_x509_certificate(self.cert_path.read_bytes())
                key = cert.public_key()
                if (
                    isinstance(key, ed25519.Ed25519PublicKey)
                    and key.public_bytes(_RAW, _RAW_PUB) == self.public_key
                ):
                    return
            except ValueError:
                pass
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"up2p-{self.device_id[:32]}")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self.signing_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365 * 50))
            .sign(self.signing_key, None)
        )
        _write_private(self.cert_path, cert.public_bytes(serialization.Encoding.PEM))


def identity_directory(data_dir: Path | str | None, app_id: str) -> Path:
    if data_dir is None:
        return default_data_dir() / app_id
    path = Path(data_dir)
    if not str(path):
        raise ConfigurationError("data_dir must not be empty")
    return path / app_id
