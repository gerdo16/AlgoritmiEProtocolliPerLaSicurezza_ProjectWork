from crypto.asymmetric import generate_rsa_key_pair
from models.certificate import Certificate
from actors.certificationauthority import CertificationAuthority

class User:
    def __init__(self, name:str, matriculation_number:str):
        self.name = name
        self.matriculation_number = matriculation_number
        self.sk, self.pk = None, None
        self.cert: "Certificate" = None
        self.ca: "CertificationAuthority" = None
        print(f"[User] Utente {self.name} creato con matricola {self.matriculation_number}")

    
    def getName(self):
        return self.name
    
    def getCertificate(self):
        return self.cert

    def getPublicKey(self):
        return self.pk
    
    def getCertificateAuthority(self):
        return self.ca

    def setCertificateAuthority(self, ca: "CertificationAuthority"):
        self.ca = ca



    # ========================== Fase Certificato utente ==========================
    def generateKeyPair(self):
        self.sk, self.pk = generate_rsa_key_pair()
        print(f"[User] Utente genera la propria Chiave privata e pubblica")


    def generateUnsignedCertificate(self):
        if self.ca is None:
            raise RuntimeError("L'utente non ha una CA assegnata!")
        
        if self.pk is None:
            raise RuntimeError("L'utente non ha generato le chiavi!")

        if self.cert is not None:
            print("[User] Utente ha già un certificato unsigned!")
            return

        issuer_name = self.ca.getName()
        subject_name = self.matriculation_number
        self.cert = Certificate(subject_name, issuer_name, self.pk)
        print(f"[User] Utente genera certificato unsigned {self.name} per la CA {issuer_name}")


    def signCertificateWithCA(self):
        if self.ca is None:
            raise RuntimeError("L'utente non ha una CA assegnata!")
        
        if self.cert is None:
            raise RuntimeError("L'utente non ha un certificato da firmare!")

        print(f"[User] Utente richiede firma del certificato alla CA di riferimento: {self.ca.getName()}")
        self.cert = self.ca.sign(self.cert)




    # ========================== Fase Trasmissione voto ==========================



    def __str__(self):
        out = f"\n=================================== User {self.name} ===================================\n"
        out += f" - Matricola: {self.matriculation_number}\n"
        out += f" - Public Key: {self.pk}\n"
        out += f" - Private Key: è privata non si può vedere :)\n"
        out += f" - Certificato: {self.cert}\n"
        out += f" - Certificato firmato: {self.cert.isSigned()}\n"
        out += f" - CA: {self.ca}\n"
        out += "=================================================================================\n"
        return out