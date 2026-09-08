"""Local RFC 3161 authority with ephemeral synthetic keys; never a production TSA."""

import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def timestamp_authority(directory: Path, *, accuracy: str | None = "secs:1"):
    directory.mkdir(parents=True, exist_ok=True)
    now = datetime.now(UTC)
    root_key, tsa_key = (rsa.generate_private_key(public_exponent=65537, key_size=2048) for _ in range(2))
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic pilot TSA root")])
    tsa_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic pilot TSA")])

    def certificate(name, public_key, ca, validity, serial):
        return (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(root_name)
            .public_key(public_key)
            .serial_number(serial)
            .not_valid_before(now - timedelta(days=2))
            .not_valid_after(now + validity)
            .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), critical=False)
            .add_extension(x509.KeyUsage(True, False, False, False, False, ca, ca, False, False), critical=True)
        )

    root = certificate(root_name, root_key.public_key(), True, timedelta(days=30), 1).sign(root_key, hashes.SHA256())
    leaf = (
        certificate(tsa_name, tsa_key.public_key(), False, timedelta(days=2), 2)
        .add_extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
        .sign(root_key, hashes.SHA256())
    )
    for name, cert in (("root.pem", root), ("tsa.pem", leaf)):
        (directory / name).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path = directory / "key.pem"
    key_path.touch(mode=0o600)
    key_path.write_bytes(
        tsa_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    (directory / "serial").write_text("01")
    config = directory / "tsa.cnf"
    accuracy_config = "" if accuracy is None else f"accuracy = {accuracy}"
    config.write_text(f"""[tsa]
default_tsa = local
[local]
serial = {directory / "serial"}
signer_cert = {directory / "tsa.pem"}
signer_key = {key_path}
signer_digest = sha256
default_policy = 1.2.3.4
digests = sha256
{accuracy_config}
clock_precision_digits = 0
ordering = yes
tsa_name = yes
ess_cert_id_chain = no
ess_cert_id_alg = sha256
""")

    def issue(request: bytes):
        query, reply = directory / "request.tsq", directory / "response.tsr"
        query.write_bytes(request)
        result = subprocess.run(
            ["openssl", "ts", "-reply", "-config", str(config), "-queryfile", str(query), "-out", str(reply)],
            capture_output=True,
            timeout=15,
        )
        if result.returncode:
            raise RuntimeError("Synthetic TSA generation failed")
        return reply.read_bytes()

    return root, leaf, issue
