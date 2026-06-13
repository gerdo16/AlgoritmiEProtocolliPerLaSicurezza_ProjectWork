from actors.certificationauthority import CertificationAuthority
from models.certificate import Certificate
from crypto.asymmetric import *
from crypto.utils import *



class Server:
    def __init__(self, name, address):
        self.name = name
        self.address = address
        self.sk, self.pk = None, None
        self.cert: "Certificate" = None
        self.ca: "CertificationAuthority" = None
        self.caAuthenticator: "Certificate" = None

        self.nonceList: set[bytes] = set() # Lista dei nonce generati dall'Authenticator per evitare replay attack

        self.voteDatabase: dict[str, int] = {"SI": 0, "NO": 0} # Database dei voti ricevuti dal Server: (#SI, #NO)
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



    def receivePckFromAuthenticator(self, pck_from_authenticator: bytes) -> bytes:
        """ Riceve un pacchetto cifrato dall'Authenticator contenente il voto dell'utente """
        print(f"[Server] Server \"{self.name}\" riceve il pacchetto dall'Authenticator contenente il voto dell'utente -> (c || nonce || sigma_A)")

        c, nonce, sigma_A = unpack_fields(pck_from_authenticator, 3)

        print(f"[Server] Server \"{self.name}\" verifica che il nonce ricevuto dall'Authenticator non sia già stato utilizzato...")
        if nonce in self.nonceList:
            raise RuntimeError("Nonce già utilizzato, possibile replay attack!")
        # self.nonceList.add(nonce) NON ancora
        print(f"[Server] Server \"{self.name}\" ha verificato che il nonce ricevuto dall'Authenticator non è stato ancora utilizzato.")

        print(f"[Server] Server \"{self.name}\" verifica la firma dell'Authenticator sul pacchetto ricevuto...")
        data_to_verify: bytes = pack_fields(c, nonce)
        if not verifySign(self.caAuthenticator.getPublicKey(), data_to_verify, sigma_A):
            raise RuntimeError("Firma dell'Authenticator non valida -> V_pk_A(c || nonce, sigma_A) = 0")
        print(f"[Server] Server \"{self.name}\" ha verificato la firma dell'Authenticator sul pacchetto ricevuto -> V_pk_A(c || nonce, sigma_A) = 1")

        print(f"[Server] Server \"{self.name}\" estrae il voto v dal messaggio cifrato c e lo memorizza nel database dei voti.")
        v:bytes = rsa_decrypt(self.sk, c)
        v:str = v.decode()
        print(f"[Server] Server \"{self.name}\" ha estratto il voto v = \"{v}\" dal messaggio cifrato c.")

        if v not in self.voteDatabase:
            raise RuntimeError(f"Voto ricevuto non valido: {v}. Voti validi sono solo 'SI' o 'NO'.")
        self.voteDatabase[v] += 1
        print(f"[Server] Server \"{self.name}\" ha registrato il voto v = \"{v}\" nel database dei voti: {self.voteDatabase} -> (#SI = {self.voteDatabase['SI']}, #NO = {self.voteDatabase['NO']})")

        # prepara l'ACK
        ACK:bytes = b"ACK"
        print(f"[Server] Server \"{self.name}\" prepara un ACK da inviare all'Authenticator per confermare la ricezione e registrazione del voto:")

        data_to_encrypt: bytes = pack_fields(ACK, nonce)
        c_S = rsa_encrypt(self.caAuthenticator.getPublicKey(), data_to_encrypt)
        print(f"[Server] Server \"{self.name}\" cifra l'ACK e il nonce con la chiave pubblica dell'Authenticator ottenendo c_S = Enc_pk_A(ACK || nonce)")

        s_S = sign(self.sk, c_S)
        print(f"[Server] Server \"{self.name}\" firma il messaggio cifrato c_S con la propria chiave privata ottenendo s_S = Enc_sk_S(c_S)")

        pck_to_authenticator: bytes = pack_fields(c_S, s_S)
        print(f"[Server] Server \"{self.name}\" ha preparato il pacchetto da inviare all'Authenticator contenente il messaggio cifrato e la firma: (c_S || s_S)")

        return pck_to_authenticator




    def __str__(self):
        return f"[Server] Server \"{self.name}\""