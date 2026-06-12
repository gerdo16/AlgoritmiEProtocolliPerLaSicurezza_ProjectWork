import crypto.asymmetric

def runFullProtocol():
    sk, pk = crypto.asymmetric.generate_rsa_key_pair()
    message = b"Hello, this is a secret message!Hello, this is a secret message!Hello, this is a secret message!Hello, this is a secret message!Hello, this is a secret message!Hello, this is a secret message!Hello, this is a secret message!Hello, this is a secret message!Hello, this is a secret message!Hello, this is a secret message!Hello, this is a secret message!Hello, this is a secret message!Hello, this is a secret messagHello, this is a secret message!Hello, this is a secret message!Hello, this is a secret message!Hello, this is a secret message!Hello, this is a secret message!Hello, this is a secret message!Hello, this is a secret message!e!"
    print("Original message:", message)
    
    cyphertext = crypto.asymmetric.encrypt(pk, message)
    print("Encrypted message:", cyphertext)
    
    decrypted_message = crypto.asymmetric.decrypt(sk, cyphertext)
    print("Decrypted message:", decrypted_message)