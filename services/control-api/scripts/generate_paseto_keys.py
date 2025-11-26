from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import secrets, sys, pathlib, datetime as dt


def main(out_dir="secrets"):
    p = pathlib.Path(out_dir);
    p.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    priv_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub = key.public_key()
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    kid = "v4-" + dt.datetime.utcnow().strftime("%Y%m") + "-" + secrets.token_hex(2)
    (p / f"paseto_{kid}.priv.pem").write_bytes(priv_pem)
    (p / f"paseto_{kid}.pub.pem").write_bytes(pub_pem)

    print("✅ Generated PASETO v4.public keys")
    print("KID:", kid)
    print("PRIVATE:", str(p / f"paseto_{kid}.priv.pem"))
    print("PUBLIC :", str(p / f"paseto_{kid}.pub.pem"))
    print("\nPut into .env or your secrets manager:")
    print(f"PASETO_KID={kid}")
    print(f"PASETO_PRIV_PEM_PATH={p / f'paseto_{kid}.priv.pem'}")
    print(f"PASETO_PUB_PEM_PATH={p / f'paseto_{kid}.pub.pem'}")


if __name__ == "__main__":
    main(*sys.argv[1:])
