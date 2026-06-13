from crypto.asymmetric import generate_rsa_key_pair
from models.certificate import Certificate
from actors.certificationauthority import CertificationAuthority

class Authenticator: 
    def __init__(self, name, address):
        self.name = name
        self.address = address
        self.sk, self.pk = None, None
        self.cert: "Certificate" = None
        self.ca: "CertificationAuthority" = None
        self.caServer: "Certificate" = None
        print(f"[Authenticator] Authenticator \"{self.name}\" creato con address \"{self.address}\"")


    def setCertificationAuthority(self, ca: "CertificationAuthority"):
        self.ca = ca

    def setCAServerCertificate(self, cert: "Certificate"):
        self.caServer = cert
    
    def getCertificate(self):
        return self.cert
    
    def getName(self):
        return self.name


    def generateKeyPair(self):
        self.sk, self.pk = generate_rsa_key_pair()
        print(f"[Authenticator] Authenticator \"{self.name}\" genera la propria Chiave privata e pubblica")


    def generateUnsignedCertificate(self):
        if self.ca is None:
            raise RuntimeError("L'authenticator non ha una CA assegnata!")
        
        if self.pk is None:
            raise RuntimeError("L'authenticator non ha generato le chiavi!")

        if self.cert is not None:
            print(f"[Authenticator] Authenticator \"{self.name}\" ha già un certificato unsigned!")
            return

        issuer_name = self.ca.getName()
        subject_name = self.name
        self.cert = Certificate(subject_name, issuer_name, self.pk)
        print(f"[Authenticator] Authenticator \"{self.name}\" genera certificato unsigned per la CA \"{issuer_name}\"")


    def signCertificateWithCA(self):
        if self.ca is None:
            raise RuntimeError("L'authenticator non ha una CA assegnata!")
        
        if self.cert is None:
            raise RuntimeError("L'authenticator non ha un certificato da firmare!")

        print(f"[Authenticator] Authenticator \"{self.name}\" chiede alla CA \"{self.ca.getName()}\" di firmare il suo certificato...")
        self.cert = self.ca.sign(self.cert)


    def verifyCertificate(self, cert: "Certificate") -> bool:
        """ Verifica che il certificato sia stato firmato dalla CA di fiducia del server """
        if self.ca is None:
            raise RuntimeError("L'authenticator non ha una CA assegnata!")
        
        if cert is None:
            raise RuntimeError("Il certificato da verificare è None!")

        print(f"[Authenticator] Authenticator \"{self.name}\" verifica che il certificato di \"{cert.getSubject()}\" sia stato firmato dalla CA \"{self.ca.getName()}\"...")
        return cert.verify(self.ca.getCertificate())


    # ========================== Fase Handshake ==========================


    def voteRequestReceive(self, user: "User") -> tuple["Certificate", "Certificate"]:
        print(f"[Authenticator] Authenticator \"{self.name}\" ha ricevuto una Vote Requeste dall'Utente \"{user.getName()}\" e restituisce i certificati firmati di Server e Authenticator.")
        return self.cert, self.caServer


    def __str__(self):
        return f"[Authenticator] Authenticator \"{self.name}\""