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


    def setCertificateAuthority(self, ca: "CertificationAuthority"):
        self.ca = ca


    def generateKeyPair(self):
        self.sk, self.pk = generate_rsa_key_pair()
        print(f"[Authenticator] Authenticator genera la propria Chiave privata e pubblica")


    def generateUnsignedCertificate(self):
        if self.ca is None:
            raise RuntimeError("L'authenticator non ha una CA assegnata!")
        
        if self.pk is None:
            raise RuntimeError("L'authenticator non ha generato le chiavi!")

        if self.cert is not None:
            print("[Authenticator] Authenticator ha già un certificato unsigned!")
            return

        issuer_name = self.ca.getName()
        subject_name = self.name
        self.cert = Certificate(subject_name, issuer_name, self.pk)
        print(f"[Authenticator] Authenticator genera certificato unsigned {self.name} per la CA {issuer_name}")


    def signCertificateWithCA(self):
        if self.ca is None:
            raise RuntimeError("L'authenticator non ha una CA assegnata!")
        
        if self.cert is None:
            raise RuntimeError("L'authenticator non ha un certificato da firmare!")

        print(f"[Authenticator] Authenticator {self.name} chiede alla CA {self.ca.getName()} di firmare il suo certificato...")
        self.cert = self.ca.sign(self.cert)


    def __str__(self):
        pass