
import base64
import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

password = ""
salt = ""

def decryptMsg(enc_msg):
    
    enc_password = password.encode()

    # Create a Sym key from salt and password
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,salt=salt,iterations=10000,backend=default_backend())
    secret_key = base64.urlsafe_b64encode(kdf.derive(enc_password))
    f_key = Fernet(secret_key)
    print(enc_msg)
    print(type(enc_msg))
    dec_msg = f_key.decrypt(bytes(enc_msg, 'utf-8'))
    print(dec_msg)

def startSocket():
    recv_socket = socket.socket()
    recv_socket.bind(('127.0.0.1',9000))
    recv_socket.listen()
    while True:
        conn, address = recv_socket.accept()
        print("Connection from: " + str(address))

        while True:
            # receive data stream. it won't accept data packet greater than 1024 bytes
            data = conn.recv(1024).decode()
            if not data:

                # if data is not received break
                break
            print("from connected user: " + str(data))
            conn.send("Got it".encode())
            break
        break
    
    conn.close()  
    decryptMsg(data)


def main():
    global salt
    global password
    # password = input("Enter password: ")
    # salt = input("Enter Salt: ")
    password = "password"
    salt = "password"

    # Convert salt to ASCII
    salt = salt.encode('ascii')
    startSocket()
    
    print("hellp")


if __name__ == "__main__":
    main()