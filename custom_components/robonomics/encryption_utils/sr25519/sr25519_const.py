# Consts for encryption
ENCRYPTION_KEY_SIZE = 32
PUBLIC_KEY_SIZE = 32
MAC_KEY_SIZE = 32
MAC_VALUE_SIZE = 32
DERIVATION_KEY_SALT_SIZE = 32
DERIVATION_KEY_ROUNDS = 2048        # Number of iterations
DERIVATION_KEY_SIZE = 64            # Desired length of the derived key
PBKDF2_HASH_ALGORITHM = 'sha512'    # Hashing algorithm
NONCE_SIZE = 24