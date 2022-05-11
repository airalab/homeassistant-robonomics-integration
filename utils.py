import nacl.secret
import base64

def encrypt(seed: str, data: str) -> str:
    b = bytes(seed[0:32], "utf8")
    box = nacl.secret.SecretBox(b)
    data = bytes(data, 'utf-8')
    encrypted = box.encrypt(data)
    text = base64.b64encode(encrypted).decode("ascii")
    return text

def decrypt(seed: str, encrypted_data: str) -> str:
    b = bytes(seed[0:32], "utf8")
    box = nacl.secret.SecretBox(b)
    decrypted = box.decrypt(base64.b64decode(encrypted_data))
    return decrypted

def str2bool(v):
  return v.lower() in ("on", "true", "t", "1", 'y', 'yes', 'yeah')