# Darin Wong

def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent = 65537, key_size = 2048)
    public_key = private_key.public_key()
    return private_key, public_key

# Signs a message by encrypting the hash of a message with the private key
def sign_message(private_key, message: str) -> bytes:
    message_bytes = message.encode('utf-8')
    signature = private_key.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# Verifies a signed message by using the sender's public key
def verify_signature(public_key, message: str, signature: bytes) -> bool:
    message_bytes = message.encode('utf-8')
    try:
        public_key.verify(
            signature,
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
