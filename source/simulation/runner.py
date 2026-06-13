import crypto.asymmetric
from models.certificate import Certificate
from actors.user import User
from actors.certificationauthority import CertificationAuthority
from actors.authenticator import Authenticator
from actors.server import Server

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

    authenticator = Authenticator("University Voting Authenticator", "authenticate.unisa.it")
    authenticator.setCertificationAuthority(ca)
    authenticator.generateKeyPair()
    authenticator.generateUnsignedCertificate()
    authenticator.signCertificateWithCA()
    #print(authenticator)

    server = Server("University Voting Server", "vote.unisa.it")
    server.setCertificationAuthority(ca)
    server.generateKeyPair()
    server.generateUnsignedCertificate()
    server.signCertificateWithCA()
    #print(server)

    sava = User("sava", "IE22700086")
    sava.setCertificationAuthority(ca)
    sava.generateKeyPair()
    sava.generateUnsignedCertificate()
    sava.signCertificateWithCA()
    #print(sava)

    print("\n\n================================================================================================================")
    print("=================================== Fine simulazione protocollo di votazione ===================================")
    print("================================================================================================================\n\n")