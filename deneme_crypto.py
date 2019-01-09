from Cryptodome import Random
from Cryptodome.Cipher import PKCS1_OAEP, AES, PKCS1_v1_5
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes


def main():
    recipient_key = RSA.import_key(open("peer_keys/154505276821948_public_key.txt").read())
    cipher = PKCS1_v1_5.new(recipient_key)
    ciphertext = cipher.encrypt("Deneme Deneme Deneme Deneme Deneme Deneme Deneme Deneme Deneme Deneme ".encode())
    print(ciphertext)
    private_key = RSA.import_key(open("peer_keys/154505276821948_private_key.txt").read())
    sentinel = Random.new().read(15)
    cipher = PKCS1_v1_5.new(private_key)
    message = cipher.decrypt(ciphertext, sentinel)
    print(message)

if __name__ == "__main__":
    main()
