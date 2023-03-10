import time
import base64
import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.fernet import Fernet

round_dict ={}

def prepareMsg(num):
    """
    This method gets message numeber and excryptes the message to deilver from file
    :param: num 
    :return: 
    """
    global round_dict
    
    # Read the message and parse it from file
    with open("messages{}.txt".format(num),"r") as msg_file:
        for line in msg_file:
            msg_txt,path,round,password,salt,dest_ip,dest_port = line.rstrip().split()
            msg_txt = msg_txt.encode()

            # Convert salt to hex
            salt = salt.encode('ascii')
            enc_password = password.encode()

            # Create a Sym key from salt and password
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,salt=salt,iterations=100000,backend=default_backend())
            secret_key = base64.urlsafe_b64encode(kdf.derive(enc_password))
            f_key = Fernet(secret_key)

            # Encrypt msg_txt using created key
            enc_msg = f_key.encrypt(msg_txt)
            

            # for hop in path.split(","):

            #     # Encrypt final message with public key of the server
            #     with open("pk{}.pem".format(hop), "rb") as pem_file:
            #         key_data = pem_file.read()

            #         # Recover the public key
            #         public_key = load_pem_public_key(key_data)

            final_msg = dest_ip+dest_port+str(enc_msg)

            # Add final message to the round dictionary to be sent later on 
            round_dict.setdefault(round,[]).append(final_msg)



def clientSocket():

    message_list = []

    # Iterate all the rounds needed from the global dictionary
    for round_num in round_dict:
        print("Round "+round_num)
        for message in round_dict[round_num]:
            print(message)
            
            # Open a socket to the target
            client_socket = socket.socket() 
            client_socket.connect(('127.0.0.1', 9000))  # connect to the server
            print("Sending: "+str(message))
            client_socket.send(message.encode())  # send message
            data = client_socket.recv(1024).decode()
            print('\nReceived from server: ' + data)
            client_socket.close()

        time.sleep(60)
    
            


def main():
   # msg_num = input("Enter Messeage Number: ")
    msg_num=1
    prepareMsg(msg_num)
    clientSocket()


if __name__ == "__main__":
    main()
