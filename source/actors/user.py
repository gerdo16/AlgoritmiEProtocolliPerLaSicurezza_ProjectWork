from crypto.asymmetric import generate_rsa_key_pair, rsa_encrypt, rsa_decrypt, sign
from models.certificate import Certificate
from actors.certificationauthority import CertificationAuthority
import random

class User:
    def __init__(self, name:str, matriculation_number:str):
        self.name = name
        self.matriculation_number = matriculation_number
        self.sk, self.pk = None, None
        self.cert: "Certificate" = None
        self.ca: "CertificationAuthority" = None
        print(f"[User] Utente \"{self.name}\" creato con matricola \"{self.matriculation_number}\"")

    
    def getName(self):
        return self.name
    
    def getCertificate(self):
        return self.cert

    def getPublicKey(self):
        return self.pk
    
    def getCertificateAuthority(self):
        return self.ca

    def setCertificationAuthority(self, ca: "CertificationAuthority"):
        self.ca = ca



    # ========================== Fase Certificato utente ==========================
    def generateKeyPair(self):
        self.sk, self.pk = generate_rsa_key_pair()
        print(f"[User] Utente \"{self.name}\" genera la propria Chiave privata e pubblica")


    def generateUnsignedCertificate(self):
        if self.ca is None:
            raise RuntimeError("L'utente non ha una CA assegnata!")
        
        if self.pk is None:
            raise RuntimeError("L'utente non ha generato le chiavi!")

        if self.cert is not None:
            print(f"[User] Utente \"{self.name}\" ha già un certificato unsigned!")
            return

        issuer_name = self.ca.getName()
        subject_name = self.matriculation_number
        self.cert = Certificate(subject_name, issuer_name, self.pk)
        print(f"[User] Utente \"{self.name}\" genera certificato unsigned per la CA \"{issuer_name}\"")


    def signCertificateWithCA(self):
        if self.ca is None:
            raise RuntimeError("L'utente non ha una CA assegnata!")
        
        if self.cert is None:
            raise RuntimeError("L'utente non ha un certificato da firmare!")

        print(f"[User] Utente \"{self.name}\" richiede firma del certificato alla CA di riferimento: {self.ca.getName()}")
        self.cert = self.ca.sign(self.cert)


    


    # ========================== Fase Trasmissione voto ==========================
    def create_Cfinal(self) -> bytes:
        """ C_final = Enc_{pk_A}(s || c || c' || Cert(U)) """

        v:str = random.choice(["SI", "NO"]) # Voto dell'utente, scelto casualmente per la simulazione
        print(f"[User] Utente \"{self.name}\" ha scelto il voto: {v}")

        pk_S = self.serverCert.getPublicKey()
        pk_A = self.authenticatorCert.getPublicKey()

        # Cifratura interna -> c = Enc_{pk_S}(v)
        c:bytes = rsa_encrypt(pk_S, v.encode())

        # Firma del cifrato -> sigma = Enc_{sk_U}(c)
        sigma:bytes = sign(self.sk, c)

        # Seconda cifratura voto -> c' = Enc_{pk_U}(v)
        c_prime:bytes = rsa_encrypt(self.pk, v.encode())

        # Cifratura esterna -> C_final = Enc_{pk_A}(s || c || c' || Cert(U))
        cert_u_bytes:bytes = self.cert.to_bytes()
        data_concatenated:bytes = sigma + c + c_prime + cert_u_bytes
        C_final:bytes = rsa_encrypt(pk_A, data_concatenated)

        print(f"[User] Utente \"{self.name}\" usa la pk_A per cifrare i dati ottenendo C_final=Enc_pkA(s || c || c' || Cert(U))")

        return C_final





    def __str__(self):
        out = f"\n=================================== User: {self.name} ===================================\n"
        out += f" - Matricola: {self.matriculation_number}\n"
        out += f" - Public Key: {self.pk}\n"
        out += f" - Private Key: è privata non si può vedere :)\n"
        out += f" - Certificato: {self.cert}\n"
        out += f" - CA: {self.ca}\n"
        out += "=================================================================================\n"
        return out