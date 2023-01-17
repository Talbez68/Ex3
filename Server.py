from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet

def createKeys():
    """
    This method gets nothing and returns a generated tuple of private and public keys
    :param: 
    :return: tuple containing the private and public keys
    """

    # Create private key object
    private_key = rsa.generate_private_key(public_exponent=65537,
                                           key_size=2048,
                                           backend=default_backend())

    # Generate private bytes
    private_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                            format=serialization.PrivateFormat.TraditionalOpenSSL,
                                            encryption_algorithm=serialization.NoEncryption())

    # Create public key object
    public_key = private_key.public_key()

    # Generate public bytes
    public_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                         format=serialization.PublicFormat.SubjectPublicKeyInfo)

    # Return tuple private and public keys
    return private_pem.decode('utf-8'), public_pem.decode('utf-8')

def main():

    pvk_num = input("Enter Private Key number: ")

    private_key,public_key = createKeys()


if __name__ == "__main__":
    main()