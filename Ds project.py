
import re
import hashlib
import bcrypt
from getpass import getpass
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend



        # ... (Register)
def is_valid_email(email):
    regex = r'^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$'
    return re.match(regex, email)


def is_valid_password(pwd):
    if len(pwd) > 8:
        return False
    if not any(char.isdigit() for char in pwd):
        return False
    if not any(char.isupper() for char in pwd):
        return False
    if not any(char.islower() for char in pwd):
        return False
    if not any(char in '!@#$%^&*()-_+=<>?' for char in pwd):
        return False
    return True


def register(email, pwd):
    if not is_valid_email(email) or not is_valid_password(pwd):
        return "Invalid input"
    with open("Enregistrement.txt", "w") as file:
        file.write(f"{email}:{pwd}\n")



        # ... (Authenticate)
def authenticate(email, pwd):
    with open("Enregistrement.txt", "r") as file:
        for line in file:
            if ':' in line:
                e,p = line.strip().split(':')
        if e == email and p == pwd:
                return True
    return False


        # ... (Hash a word)
def hash_sha256(word):
    return hashlib.sha256(word.encode()).hexdigest()


def hash_with_salt(word):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(word.encode(), salt)


        # ... (Generate RSA keys)
def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                            format=serialization.PrivateFormat.PKCS8,
                                            encryption_algorithm=serialization.NoEncryption())
    public_pem = private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                       format=serialization.PublicFormat.SubjectPublicKeyInfo)
    with open("private_key.pem", "wb") as private_file:
        private_file.write(private_pem)
    with open("public_key.pem", "wb") as public_file:
        public_file.write(public_pem)


        # ... (Encrypt/Decrypt RSA)
def encrypt_rsa(message, public_key_path):
    with open(public_key_path, "rb") as public_file:
        public_key = serialization.load_pem_public_key(public_file.read())
    ciphertext = public_key.encrypt(message.encode(),
                                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
                                                 label=None))
    return ciphertext


def decrypt_rsa(ciphertext, private_key_path):
    with open(private_key_path, "rb") as private_file:
        private_key = serialization.load_pem_private_key(private_file.read(), password=None)
    plaintext = private_key.decrypt(ciphertext,
                                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
                                                 label=None))
    return plaintext.decode()



        # ... (Sign a message with RSA)
def sign_rsa(message, private_key_path):
    with open(private_key_path, "rb") as private_file:
        private_key = serialization.load_pem_private_key(private_file.read(), password=None)
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature



        # ... (Verify RSA signature)
def verify_signature(message, signature, public_key_path):
    with open(public_key_path, "rb") as public_file:
        public_key = serialization.load_pem_public_key(public_file.read())
    try:
        public_key.verify(
            signature,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
    


        # ... (Generate Self-Signed Certificate)
def generate_self_signed_certificate(private_key_path, certificate_path):
        private_key = None
        with open(private_key_path, "rb") as private_file:
            private_key = serialization.load_pem_private_key(private_file.read(), password=None)

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Organization"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Common Name"),
        ])

        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            private_key.public_key()
        ).serial_number(x509.random_serial_number()).not_valid_before(datetime.utcnow()).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).sign(private_key, hashes.SHA256(), default_backend())

        with open(certificate_path, "wb") as cert_file:
            cert_file.write(cert.public_bytes(serialization.Encoding.PEM))




        # ... (Encrypt Message with Certificate)
def encrypt_message_with_certificate(certificate_path, message):
    with open(certificate_path, "rb") as cert_file:
        cert = x509.load_pem_x509_certificate(cert_file.read(), default_backend())
    public_key = cert.public_key()

    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return ciphertext


        # ... (Menu principal)
def main_menu():
    while True:
        print("Main Menu:")
        print("1. Register")
        print("2. Authenticate")
        print("3. Hash a word")
        print("4. Generate RSA keys")
        print("5. Encrypt/Decrypt RSA")
        print("6. Sign a message with RSA")
        print("7. Verify RSA signature")
        print("8. Generate Self-Signed Certificate")
        print("9. Encrypt Message with Certificate")
        print("10. Exit")

        choice = input("Select an option (1/2/3/4/5/6): ")

        if choice == '1':
            email = input("Enter email for registration: ")
            pwd = getpass("Enter password: ")
            print(register(email,pwd))
        elif choice == '2':
            email = input("Enter email for authentication: ")
            pwd = getpass("Enter password for authentication: ")
            if authenticate(email,pwd):
                print("Authenticated!")
            else:
                print("Failed to authenticate!")
        elif choice == '3':
            word = input("Enter a word to hash: ")
            print("SHA256 hash:", hash_sha256(word))
            print("Hash with salt:", hash_with_salt(word))
        elif choice == '4':
            generate_rsa_keys()
            print("RSA keys generated.")
        elif choice == '5':
            message = input("Enter a message to encrypt using RSA: ")
            encrypted_message = encrypt_rsa(message, "public_key.pem")
            print("Encrypted message:", encrypted_message)
            decrypted_message = decrypt_rsa(encrypted_message, "private_key.pem")
            print("Decrypted message:", decrypted_message)
        elif choice == '6':
            message_to_sign = input("Enter a message to sign with RSA: ")
            signature = sign_rsa(message_to_sign, "private_key.pem")
            print("Message signed.")
        elif choice == '7':
            message_to_verify = input("Enter a message to verify its RSA signature: ")
            provided_signature = input("Enter the provided signature: ")
            if verify_signature(message_to_verify, provided_signature, "public_key.pem"):
                print("Signature is valid.")
            else:
                print("Signature is not valid.")
        elif choice == '8':
            generate_self_signed_certificate("private_key.pem", "self_signed_certificate.pem")
            print("Self-Signed Certificate generated.")
        elif choice == '9':
            message_to_encrypt = input("Enter a message to encrypt with the certificate: ")
            encrypted_message = encrypt_message_with_certificate("self_signed_certificate.pem", message_to_encrypt)
            print("Message encrypted with the certificate:", encrypted_message)
        elif choice == '10':
            print("Exiting the program. Goodbye!")
            break
        else:
            print("Invalid option. Please choose a valid option (1/2/3/4/5/6/7/8/9/10).")

if __name__ == '__main__':
    main_menu()
