import crypto.asymmetric
from models.certificate import Certificate
from actors.user import User
from actors.certificateauthority import CertificationAuthority

def runFullProtocol():
    #sk, pk = crypto.asymmetric.generate_rsa_key_pair()
    #sk_u, pk_u = crypto.asymmetric.generate_rsa_key_pair()

    #cert_ca = Certificate("ca", "ca", pk)
    #cert_ca.sign(sk)

    #cert_u = Certificate("gerardo", "ca", pk_u)
    #cert_u.sign(sk)

    print("\n\n================================================================================================================")
    print("================================== Inizio simulazione protocollo di votazione ==================================")
    print("================================================================================================================\n\n")

    ca = CertificationAuthority("University Voting CA", "vote.unisa.it")
    ca.autoSignCertificate()
    #print(ca)

    sava = User("sava", "IE22700086")
    #print(sava)
    sava.setCertificateAuthority(ca)
    sava.generateKeyPair()
    sava.generateUnsignedCertificate()
    sava.signCertificateWithCA()
    print(sava)