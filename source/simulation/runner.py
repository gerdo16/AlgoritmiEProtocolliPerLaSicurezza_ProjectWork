import crypto.asymmetric

def runFullProtocol():
    sk, pk = crypto.asymmetric.generate_rsa_key_pair()