from crypto.asymmetric import *
from models.certificate import Certificate
from actors.certificationauthority import CertificationAuthority
import random
from actors.authenticator import Authenticator
import crypto.utils as utils

class User:
    def __init__(self, name:str, matriculation_number:str):
        self.name = name
        self.matriculation_number = matriculation_number
        self.sk, self.pk = None, None
        self.cert: "Certificate" = None
        self.ca: "CertificationAuthority" = None
        self.serverCert = None
        self.authenticatorCert = None
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



    # ========================== Fase Handshake ==========================
    def voteRequestSend(self, authenticator: "Authenticator"):
        print(f"[User] Utente \"{self.name}\" trasmette un messaggio di Vote Request all'Autheticator: {authenticator.getName()}")
        
        self.authenticatorCert, self.serverCert = authenticator.voteRequestReceive(self)

        if self.authenticatorCert is None:
            raise RuntimeError("Certificato dell'Authenticator non esistente.")
        if self.serverCert is None:
            raise RuntimeError("Certificato del Server non esistente.")
    

    def verifyCertificates(self):
        print(f"[User] Utente \"{self.name}\" verifica il certificato dell'Authenticator con la chiave pubblica della Certification Authority.")

        if self.authenticatorCert.verify(self.ca.getCertificate()) == 0:
            raise RuntimeError("Certificato dell'Authenticator non valido.")
        
        print(f"[User] Utente \"{self.name}\" ha validato il certificato dell'Authenticator.")
        print(f"[User] Utente \"{self.name}\" verifica il certificato del Server con la chiave pubblica della Certification Authority.")

        if self.serverCert.verify(self.ca.getCertificate()) == 0:
            raise RuntimeError("Certificato del Server non valido.")

        print(f"[User] Utente \"{self.name}\" ha validato il certificato del Server.")



    # ========================== Fase Trasmissione voto ==========================
    def createCfinal(self) -> bytes:
        """ C_final = Enc_{pk_A}(s || c || c' || Cert(U)) """

        v:str = random.choice(["SI", "NO"]) # Voto dell'utente, scelto casualmente per la simulazione
        print(f"[User] Utente \"{self.name}\" ha scelto il voto: {v}")

        pk_S = self.serverCert.getPublicKey()
        pk_A = self.authenticatorCert.getPublicKey()

        # Cifratura interna -> c = Enc_{pk_S}(v)
        c:bytes = rsa_encrypt(pk_S, v.encode())
        print(f"[User] Utente \"{self.name}\" usa la pk_S per cifrare il voto ottenendo c=Enc_pkS(v)")

        # Firma del cifrato -> sigma = Enc_{sk_U}(c)
        sigma:bytes = sign(self.sk, c)
        print(f"[User] Utente \"{self.name}\" usa la propria chiave privata per firmare c ottenendo sigma=Sign_skU(c)")

        # Seconda cifratura voto -> c' = Enc_{pk_U}(v)
        c_prime:bytes = rsa_encrypt(self.pk, v.encode())
        print(f"[User] Utente \"{self.name}\" usa la pk_U per cifrare il voto ottenendo c'=Enc_pkU(v)")

        # Cifratura esterna -> C_final = Enc_{pk_A}(s || c || c' || Cert(U))
        cert_u_bytes:bytes = self.cert.to_bytes()
        data_concatenated:bytes = utils.pack_fields(sigma, c, c_prime, cert_u_bytes)
        C_final_chunks: list[bytes] = rsa_encrypt_chunks(pk_A, data_concatenated)

        print(f"[User] Utente \"{self.name}\" usa la pk_A per cifrare i dati ottenendo C_final=Enc_pkA(s || c || c' || Cert(U))")

        return C_final_chunks


    def receiveAckFromAuthenticator(self, msg: List[bytes]):
        print(f"[User] Utente \"{self.name}\" ha ricevuto un messaggio dall'Authenticator.")

        decrypted_msg = rsa_decrypt_chunks(private_key=self.sk, encrypted_chunks=msg)
        print(f"[User] Utente \"{self.name}\" ha decifrato il messaggio ricevuto dall'Authenticator.")

        unpacked_msg = utils.unpack_fields(decrypted_msg, 2)
        sigma, ack = unpacked_msg[0], unpacked_msg[1]

        if not verifySign(public_key=self.authenticatorCert.getPublicKey(), message=ack, signature=sigma):
            raise RuntimeError("Firma non valida.")
        print(f"[User] Utente \"{self.name}\" ha verificato correttamente la firma del messaggio.")
        print(f"[User] Utente \"{self.name}\" ha concluso la sua votazione correttamente, conscio che il suo voto sia stato registrato.")



    def __str__(self):
        out = f"\n=================================== User: {self.name} ===================================\n"
        out += f" - Matricola: {self.matriculation_number}\n"
        out += f" - Public Key: {self.pk}\n"
        out += f" - Private Key: è privata non si può vedere :)\n"
        out += f" - Certificato: {self.cert}\n"
        out += f" - CA: {self.ca}\n"
        out += "=================================================================================\n"
        return out