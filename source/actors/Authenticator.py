from crypto.asymmetric import *
from crypto.utils import *
from models.certificate import Certificate
from actors.certificationauthority import CertificationAuthority
from cryptography.hazmat.primitives import serialization


class Authenticator: 
    def __init__(self, name, address):
        self.name = name
        self.address = address
        self.sk, self.pk = None, None
        self.cert: "Certificate" = None
        self.ca: "CertificationAuthority" = None
        self.caServer: "Certificate" = None
        self.voterMap: dict[bytes, bytes] = {} # Mappa per tenere traccia dei voti già ricevuti (chiave: H(pk_U) in bytes, valore: c' in bytes)
        self.tempVote: tuple[bytes, bytes, "Certificate"] = None
        self.buffer = None
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
    def voteRequestReceive(self, user) -> tuple["Certificate", "Certificate"]:
        print(f"[Authenticator] Authenticator \"{self.name}\" ha ricevuto una Vote Requeste dall'Utente \"{user.getName()}\" e restituisce i certificati firmati di Server e Authenticator.")
        return self.cert, self.caServer



    # ========================== Fase trasmissione voto ==========================
    def receiveCfinal(self, C_final: list[bytes]):
        print(f"[Authenticator] Authenticator \"{self.name}\" ha ricevuto C_final.")

        # Decifrazione iniziale -> Dec_{sk_A}(C_final) = (s || c || c' || Cert(U))
        data_concatenated: bytes = rsa_decrypt_chunks(self.sk, C_final)
        s, c, c_prime, cert_user_bytes = unpack_fields(data_concatenated, 4)
        print(f"[Authenticator] Authenticator \"{self.name}\" usa la propria chiave privata per decifrare C_final ottenendo (s || c || c' || Cert(U))")

        # Verifica della legittimita' dell’utente
        cert_user = Certificate.from_bytes(cert_user_bytes)
        print(f"[Authenticator] Authenticator \"{self.name}\" verifica la legittimità dell'utente verificando il certificato con la chiave pubblica della CA...")
        if cert_user.verify(self.ca.getCertificate()) == False:
            raise RuntimeError("Certificato dell'utente non valido.")
        print(f"[Authenticator] Authenticator \"{self.name}\" ha validato il certificato dell'utente.")

        # Verifica della firma e dell’integrita'
        if verifySign(cert_user.getPublicKey(), c, s) == False:
            raise RuntimeError("La firma del voto non è valida.")
        print(f"[Authenticator] Authenticator \"{self.name}\" ha verificato la firma del voto -> messaggio autenticato e integro.")

        # Verifica dell’unicita' del voto
        pk_u_bytes = cert_user.getPublicKeyBytes()
        pk_u_hash = sha256(pk_u_bytes)
        if pk_u_hash in self.voterMap:
            raise RuntimeError("L'utente ha già votato!")
        print(f"[Authenticator] Authenticator \"{self.name}\" ha verificato che l'utente non abbia già votato controllando la VoterMap.")

        self.tempVote = (c, c_prime, cert_user)



    def __str__(self):
        return f"[Authenticator] Authenticator \"{self.name}\""