from actors.certificationauthority import CertificationAuthority
from models.certificate import Certificate
from crypto.asymmetric import generate_rsa_key_pair


class Server:
    def __init__(self, name, address):
        self.name = name
        self.address = address
        self.sk, self.pk = None, None
        self.cert: "Certificate" = None
        self.ca: "CertificationAuthority" = None
        self.caAuthenticator: "Certificate" = None
        print(f"[Server] Server \"{self.name}\" creato con address \"{self.address}\"")



    def setCertificationAuthority(self, ca: "CertificationAuthority"):
        self.ca = ca

    def setCAAuthenticatorCertificate(self, cert: "Certificate"):
        self.caAuthenticator = cert

    def getCertificate(self):
        return self.cert


    def generateKeyPair(self):
        self.sk, self.pk = generate_rsa_key_pair()
        print(f"[Server] Server \"{self.name}\" genera la propria Chiave privata e pubblica")


    def generateUnsignedCertificate(self):
        if self.ca is None:
            raise RuntimeError("Il server non ha una CA assegnata!")
        
        if self.pk is None:
            raise RuntimeError("Il server non ha generato le chiavi!")

        if self.cert is not None:
            print(f"[Server] Server \"{self.name}\" ha già un certificato unsigned!")
            return

        issuer_name = self.ca.getName()
        subject_name = self.name
        self.cert = Certificate(subject_name, issuer_name, self.pk)
        print(f"[Server] Server \"{self.name}\" genera certificato unsigned per la CA \"{issuer_name}\"")


    def signCertificateWithCA(self):
        if self.ca is None:
            raise RuntimeError("Il server non ha una CA assegnata!")
        
        if self.cert is None:
            raise RuntimeError("Il server non ha un certificato da firmare!")

        print(f"[Server] Server \"{self.name}\" chiede alla CA \"{self.ca.getName()}\" di firmare il suo certificato...")
        self.cert = self.ca.sign(self.cert)

    
    def verifyCertificate(self, cert: "Certificate") -> bool:
        """ Verifica che il certificato sia stato firmato dalla CA di fiducia del server """
        if self.ca is None:
            raise RuntimeError("Il server non ha una CA assegnata!")
        
        if cert is None:
            raise RuntimeError("Il certificato da verificare è None!")

        print(f"[Server] Server \"{self.name}\" verifica che il certificato di \"{cert.getSubject()}\" sia stato firmato dalla CA \"{self.ca.getName()}\"...")
        return cert.verify(self.ca.getCertificate())



    def __str__(self):
        return f"[Server] Server \"{self.name}\""