from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# Generar el par de claves RSA
def Generar_claves_RSA():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Cifrar un mensaje usando la clave pública
def cifrar_mensaje(public_key, message):
    ciphertext = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

# Descifrar el mensaje usando la clave privada
def descifrar_mensaje(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode('utf-8')

# Guardar las claves en archivos
def guardar_llaves(private_key, public_key):
    # Guardar clave privada
    with open("private_key.pem", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Guardar clave pública
    with open("public_key.pem", "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

# Cargar las claves desde archivos
def load_keys():
    # Cargar clave privada
    with open("private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
        )

    # Cargar clave pública
    with open("public_key.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
        )

    return private_key, public_key

# Ejemplo de uso
private_key, public_key = Generar_claves_RSA()
guardar_llaves(private_key, public_key)

message = "Este es un mensaje secreto."
print("Mensaje original:", message)

ciphertext = cifrar_mensaje(public_key, message)
print("Mensaje cifrado:", ciphertext)

private_key, public_key = load_keys()
decrypted_message = descifrar_mensaje(private_key, ciphertext)
print("Mensaje descifrado:", decrypted_message)
