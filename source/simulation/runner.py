import crypto.asymmetric
from models.certificate import Certificate
from actors.user import User
from actors.certificationauthority import CertificationAuthority
from actors.authenticator import Authenticator
from actors.server import Server

def runFullProtocol():
    print("\n\n================================================================================================================")
    print("================================== Inizio simulazione protocollo di votazione ==================================")
    print("================================================================================================================\n\n")

    print("===================================================== Fase preliminare del sistema ==========================================================\n\n")

    ca = CertificationAuthority("University Voting CA", "vote.unisa.it")
    ca.autoSignCertificate()

    authenticator = Authenticator("University Voting Authenticator", "authenticate.unisa.it")
    authenticator.setCertificationAuthority(ca)
    authenticator.generateKeyPair()
    authenticator.generateUnsignedCertificate()
    authenticator.signCertificateWithCA()

    server = Server("University Voting Server", "vote.unisa.it")
    server.setCertificationAuthority(ca)
    server.generateKeyPair()
    server.generateUnsignedCertificate()
    server.signCertificateWithCA()

    if authenticator.verifyCertificate(server.getCertificate()):
        authenticator.setCAServerCertificate(server.getCertificate())
    if server.verifyCertificate(authenticator.getCertificate()):
        server.setCAAuthenticatorCertificate(authenticator.getCertificate())    

    user = User("sava", "IE22700086")
    user.setCertificationAuthority(ca)
    user.generateKeyPair()
    user.generateUnsignedCertificate()
    user.signCertificateWithCA()

    print("\n\n===================================================== Fase di handshake ==========================================================\n\n")
    
    user.voteRequestSend(authenticator=authenticator)
    user.verifyCertificates()


    print("\n\n================================================================================================================")
    print("=================================== Fine simulazione protocollo di votazione ===================================")
    print("================================================================================================================\n\n")