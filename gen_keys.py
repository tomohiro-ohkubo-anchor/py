import secrets

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from dotenv import load_dotenv
from nacl.signing import SigningKey

load_dotenv()



def generate_keys() -> tuple[str, str]:
    seed: bytes = secrets.token_bytes(32)
    skey = SigningKey(seed)
    return skey.encode().hex(), skey.verify_key.encode().hex()




if __name__ == '__main__':
    priv, pub = generate_keys()
    print(f'private key:\n{priv}\n')
    print(f'public key:\n{pub}\n')
