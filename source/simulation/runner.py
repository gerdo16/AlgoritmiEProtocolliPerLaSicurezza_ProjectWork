import crypto.asymmetric
from models.certificate import Certificate

def runFullProtocol():
    sk, pk = crypto.asymmetric.generate_rsa_key_pair()
    sk_u, pk_u = crypto.asymmetric.generate_rsa_key_pair()

    cert_ca = Certificate("ca", "ca", pk)
    cert_ca.sign(sk)

    cert_u = Certificate("gerardo", "ca", pk_u)
    #cert_u.sign(sk)

    