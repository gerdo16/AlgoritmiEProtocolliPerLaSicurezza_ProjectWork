import random

from crypto.asymmetric import *
from crypto.utils import *
from models.certificate import Certificate
from actors.certificationauthority import CertificationAuthority
from cryptography.hazmat.primitives import serialization
import os


class Authenticator: 
    def __init__(self, name, address):
        self.name = name
        self.address = address
        self.sk, self.pk = None, None
        self.cert: "Certificate" = None
        self.ca: "CertificationAuthority" = None
        self.caServer: "Certificate" = None

        self.voterMap: dict[bytes, bytes] = {} # Mappa per tenere traccia dei voti già ricevuti: [H(pk_U) -> c']
        self.tempVote: tuple[bytes, bytes, "Certificate"] = None

        self.buffer: list[tuple[bytes, bytes]] = [] # Buffer come lista di messaggi da inviare al Server: lista di [H(pk_U), (c || nonce || sigma_A)], solo (c || nonce || sigma_A) si deve mandare al Server, H(pk_U) serve per la gestione del buffer e per la conferma del voto da parte del Server
        self.pendingVote: tuple[bytes, bytes, bytes] = None # Voto in attesa di essere confermato dal Server (H(pk_U), nonce, c')

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
            raise RuntimeError("La firma del voto non è valida ->  -> V_pk_U(c, s) = 0")
        print(f"[Authenticator] Authenticator \"{self.name}\" ha verificato la firma del voto: messaggio autenticato e integro -> V_pk_U(c, s) = 1")

        # Verifica dell’unicita' del voto
        pk_u_bytes = cert_user.getPublicKeyBytes()
        pk_u_hash = sha256(pk_u_bytes)
        if pk_u_hash in self.voterMap:
            raise RuntimeError("L'utente ha già votato!")
        print(f"[Authenticator] Authenticator \"{self.name}\" ha verificato che l'utente non abbia già votato controllando la VoterMap.")

        self.tempVote = (c, c_prime, cert_user)

    def bufferingVote(self):
        if self.tempVote is None:
            raise RuntimeError("Nessun voto da bufferizzare.")
        
        c, c_prime, cert_user = self.tempVote

        # Preparazione del messaggio per S
        nonce: bytes = os.urandom(16)
        print(f"[Authenticator] Authenticator \"{self.name}\" genera il nonce: {nonce}")

        # sigma_A = Sign_skA(c || nonce) = Sign_skA(Enc_pkS(v) || nonce)
        data_to_sign: bytes = pack_fields(c, nonce)
        sigma_A = sign(self.sk, data_to_sign)
        print(f"[Authenticator] Authenticator \"{self.name}\" firma il messaggio (c || nonce) ottenendo sigma_A=Sign_skA(c || nonce)")

        pck_to_server: bytes = pack_fields(c, nonce, sigma_A)
        print(f"[Authenticator] Authenticator \"{self.name}\" è pronto il messaggio da inviare al Server: (c || nonce || sigma_A)")

        # bufferizzazione del messaggio da inviare al Server
        self.buffer.append((sha256(cert_user.getPublicKeyBytes()), pck_to_server))
        print(f"[Authenticator] Authenticator \"{self.name}\" bufferizza il messaggio da inviare al Server nella mappa buffer: [H(pk_U) -> (c || nonce || sigma_A)]")

    def sendPckToServer(self) -> bytes:
        """ Estrae un messaggio dal buffer e lo restituisce per inviarlo al Server """
        if len(self.buffer) == 0:
            raise RuntimeError("Nessun messaggio da inviare al Server.")

        # Estrazione casuale di un messaggio dal buffer
        pk_u_hash, pck_to_server = self.buffer.pop(random.randint(0, len(self.buffer) - 1))
        print(f"[Authenticator] Authenticator \"{self.name}\" estrae un messaggio dal buffer per inviarlo al Server.")

        nonce = unpack_fields(pck_to_server, 3)[1] # Estraggo solo il nonce dal pacchetto da inviare al Server
        self.pendingVote = (pk_u_hash, nonce, self.tempVote[1]) # Salvo il voto in attesa di conferma dal Server (H(pk_U), nonce, c')

        return pck_to_server
    
    def receiveAckFromServer(self, pck_from_server: bytes):
        unpack_from_server = unpack_fields(pck_from_server, 2)
        c_S, s_S = unpack_from_server[0], unpack_from_server[1]
        print(f"[Authenticator] Authenticator \"{self.name}\" riceve un pacchetto dal Server.")
        
        if not verifySign(self.caServer.getPublicKey(), c_S, s_S):
            raise RuntimeError("Messaggio potenzialmente manipolato.")
        print(f"[Authenticator] Authenticator \"{self.name}\" verifica correttamente la firma del messaggio ricevuto.")

        decrypted_data = rsa_decrypt(private_key=self.sk, ciphertext=c_S)
        print(f"[Authenticator] Authenticator \"{self.name}\" decifra correttamente il messaggio.")

        message = unpack_fields(decrypted_data, 2)
        ack, nonce = message[0], message[1]
        
        if not ack == b"ACK":
            raise RuntimeError("Il messaggio ricevuto non è un ACK.")
        print(f"[Authenticator] Authenticator \"{self.name}\" ha ricevuto un messaggio di tipo ACK dal Server.")

        if not nonce == self.pendingVote[1]:
            raise RuntimeError("Ack di un altro pacchetto.")
        print(f"[Authenticator] Authenticator \"{self.name}\" ha ricevuto correttamente l'ACK del voto inviato al Server.")
        self.voterMap[self.pendingVote[0]] = self.pendingVote[2]  # pendingvote[0]: hash della chiave dell'utente; pendingvote[2]: voto cifrato dell'utente.
        self.pendingVote = None


    def prepareAckForUser(self, pk) -> List[bytes]:
        print(f"[Authenticator] Authenticator \"{self.name}\" prepara ACK da inviare all'Utente.")
        
        sigma = sign(self.sk, b"ACK")
        print(f"[Authenticator] Authenticator \"{self.name}\" ha firmato correttamente l'ACK.")

        pack = pack_fields(sigma, b"ACK")
        c_final = rsa_encrypt_chunks(public_key=pk, plaintext=pack)
        print(f"[Authenticator] Authenticator \"{self.name}\" ha costruito il messaggio da inviare all'Utente.")

        return c_final

    def __str__(self):
        return f"[Authenticator] Authenticator \"{self.name}\""