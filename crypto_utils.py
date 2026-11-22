import base64
import hashlib
from typing import Optional, Tuple, Dict

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa


def compute_sha256(data: bytes) -> str:
    """Return the lowercase hexadecimal SHA-256 hash of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def generate_keypair(
    algorithm: str = "RSA-PSS",
    rsa_key_size: int = 2048,
    passphrase: Optional[str] = None,
) -> Tuple[bytes, bytes]:
    """
    Generate an asymmetric private/public key pair in PEM format.
    Supports 'RSA-PSS' (2048/3072/4096 bits) and 'Ed25519'.
    """
    if algorithm == "RSA-PSS":
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=rsa_key_size,
        )
    elif algorithm == "Ed25519":
        private_key = ed25519.Ed25519PrivateKey.generate()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    if passphrase:
        encryption = serialization.BestAvailableEncryption(passphrase.encode("utf-8"))
    else:
        encryption = serialization.NoEncryption()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return private_pem, public_pem


def sign_data(
    data: bytes,
    private_key_pem: bytes,
    passphrase: Optional[str] = None,
) -> Dict[str, str]:
    """
    Sign arbitrary bytes using a PEM-encoded RSA or Ed25519 private key.
    Returns algorithm used, SHA-256 digest, and Base64-encoded signature.
    """
    password = passphrase.encode("utf-8") if passphrase else None
    private_key = serialization.load_pem_private_key(private_key_pem, password=password)

    if isinstance(private_key, rsa.RSAPrivateKey):
        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        algo_name = f"RSA-{private_key.key_size} (PSS + SHA-256)"
    elif isinstance(private_key, ed25519.Ed25519PrivateKey):
        signature = private_key.sign(data)
        algo_name = "Ed25519 (EdDSA)"
    else:
        raise ValueError("Unsupported private key type. Use RSA or Ed25519.")

    return {
        "algorithm": algo_name,
        "sha256": compute_sha256(data),
        "signature_b64": base64.b64encode(signature).decode("ascii"),
    }


def verify_data(
    data: bytes,
    signature_b64: str,
    public_key_pem: bytes,
) -> Tuple[bool, str, str]:
    """
    Verify a Base64-encoded digital signature against raw bytes and a PEM public key.
    Returns (is_valid, algorithm_name, status_message).
    """
    try:
        cleaned_sig = "".join(signature_b64.split())
        signature = base64.b64decode(cleaned_sig, validate=True)
    except Exception:
        return False, "Unknown", "Invalid Base64 signature format."

    try:
        public_key = serialization.load_pem_public_key(public_key_pem)
    except Exception as exc:
        return False, "Unknown", f"Invalid public key PEM: {exc}"

    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            algo_name = f"RSA-{public_key.key_size} (PSS + SHA-256)"
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            algo_name = "Ed25519 (EdDSA)"
            public_key.verify(signature, data)
        else:
            return False, "Unsupported", "Unsupported public key type."

        return True, algo_name, "Signature is VALID. Message authenticity and integrity confirmed."
    except InvalidSignature:
        return False, algo_name, "Signature is INVALID. Message was tampered with or signed by a different key."
    except Exception as exc:
        return False, "Error", f"Verification failed: {exc}"
