import random

from crypto.asymmetric import *
from crypto.utils import *
from model.certificate import Certificate
from actors.certificationauthority import CertificationAuthority
from cryptography.hazmat.primitives import serialization
import os
from typing import List
from actors.constants import PRINT_START_AUTHENTICATOR


class Authenticator: 
    def __init__(self, name, address, verbose: bool = True):
        self.name = name
        self.address = address
        self.sk, self.pk = None, None
        self.cert: "Certificate" = None
        self.ca: "CertificationAuthority" = None
        self.serverCert: "Certificate" = None

        self.voterMap: dict[bytes, bytes] = {} # Mappa per tenere traccia dei voti già ricevuti: [H(pk_U) -> c']
        self.tempVote: tuple[bytes, bytes, "Certificate"] = None

        self.buffer: list[tuple[bytes, bytes]] = [] # Buffer come lista di messaggi da inviare al Server: lista di [H(pk_U), (c || nonce || sigma_A)], solo (c || nonce || sigma_A) si deve mandare al Server, H(pk_U) serve per la gestione del buffer e per la conferma del voto da parte del Server
        self.pendingVote: tuple[bytes, bytes, bytes] = None # Voto in attesa di essere confermato dal Server (H(pk_U), nonce, c')

        print(f"{PRINT_START_AUTHENTICATOR} Authenticator \"{self.name}\" creato con address \"{self.address}\"") if verbose else None



    def setCertificationAuthority(self, ca: "CertificationAuthority"):
        self.ca = ca

    def setCAServerCertificate(self, cert: "Certificate"):
        self.serverCert = cert
    
    def getCertificate(self):
        return self.cert
    
    def getName(self):
        return self.name



    # ========================== Fase preliminare del sistema ==========================

    def generateKeyPair(self, verbose: bool = True):
        self.sk, self.pk = generate_rsa_key_pair()
        print(f"{PRINT_START_AUTHENTICATOR} Authenticator \"{self.name}\" genera la propria Chiave privata e pubblica") if verbose else None


    def generateUnsignedCertificate(self, verbose: bool = True):
        if self.ca is None:
            raise RuntimeError("L'authenticator non ha una CA assegnata!")
        
        if self.pk is None:
            raise RuntimeError("L'authenticator non ha generato le chiavi!")

        if self.cert is not None:
            print(f"{PRINT_START_AUTHENTICATOR} Authenticator \"{self.name}\" ha già un certificato unsigned!") if verbose else None
            return

        issuer_name = self.ca.getName()
        subject_name = self.name
        self.cert = Certificate(subject_name, issuer_name, self.pk, verbose)
        print(f"{PRINT_START_AUTHENTICATOR} Authenticator \"{self.name}\" genera certificato unsigned per la CA \"{issuer_name}\"") if verbose else None


    def signCertificateWithCA(self, verbose: bool = True):
        if self.ca is None:
            raise RuntimeError("L'authenticator non ha una CA assegnata!")
        
        if self.cert is None:
            raise RuntimeError("L'authenticator non ha un certificato da firmare!")

        print(f"{PRINT_START_AUTHENTICATOR} Authenticator \"{self.name}\" chiede alla CA \"{self.ca.getName()}\" di firmare il suo certificato...") if verbose else None
        self.cert = self.ca.sign(self.cert, verbose)


    def verifyCertificate(self, cert: "Certificate", verbose: bool = True) -> bool:
        """ Verifica che il certificato sia stato firmato dalla CA di fiducia del server """
        if self.ca is None:
            raise RuntimeError("L'authenticator non ha una CA assegnata!")
        
        if cert is None:
            raise RuntimeError("Il certificato da verificare è None!")

        print(f"{PRINT_START_AUTHENTICATOR} Authenticator \"{self.name}\" verifica che il certificato di \"{cert.getSubject()}\" sia stato firmato dalla CA \"{self.ca.getName()}\"...") if verbose else None
        return cert.verify(self.ca.getCertificate())



    # ========================== Fase Handshake ==========================
    def voteRequestReceive(self, user, verbose: bool = True) -> tuple["Certificate", "Certificate"]:
        print(f"{PRINT_START_AUTHENTICATOR} Authenticator \"{self.name}\" ha ricevuto una Vote Requeste dall'Utente \"{user.getName()}\" e restituisce i certificati firmati di Server e Authenticator.") if verbose else None
        return self.cert, self.serverCert



    # ========================== Fase trasmissione voto ==========================
    def receiveCfinal(self, C_final: list[bytes], verbose: bool = True):
        print(f"{PRINT_START_AUTHENTICATOR} Authenticator \"{self.name}\" ha ricevuto C_final.") if verbose else None

        # Decifrazione iniziale -> Dec_{sk_A}(C_final) = (s || c || c' || Cert(U))
        data_concatenated: bytes = rsa_decrypt_chunks(self.sk, C_final)
        s, c, c_prime, cert_user_bytes = unpack_fields(data_concatenated, 4)
        print(f"{PRINT_START_AUTHENTICATOR} Authenticator \"{self.name}\" usa la propria chiave privata per decifrare C_final ottenendo (s || c || c' || Cert(U))") if verbose else None

        # Verifica della legittimita' dell’utente
        cert_user = Certificate.from_bytes(cert_user_bytes)
        print(f"{PRINT_START_AUTHENTICATOR} Authenticator \"{self.name}\" verifica la legittimità dell'utente verificando il certificato con la chiave pubblica della CA...") if verbose else None
        if cert_user.verify(self.ca.getCertificate()) == False:
            raise RuntimeError("Certificato dell'utente non valido.")
        print(f"{PRINT_START_AUTHENTICATOR} Authenticator \"{self.name}\" ha validato il certificato dell'utente.") if verbose else None

        # Verifica della firma e dell’integrita'
        if verifySign(cert_user.getPublicKey(), c, s) == False:
            raise RuntimeError("La firma del voto non è valida ->  -> V_pk_U(c, s) = 0")
        print(f"{PRINT_START_AUTHENTICATOR} Authenticator \"{self.name}\" ha verificato la firma del voto: messaggio autenticato e integro -> V_pk_U(c, s) = 1") if verbose else None

        # Verifica dell’unicita' del voto
        pk_u_bytes = cert_user.getPublicKeyBytes()
        pk_u_hash = sha256(pk_u_bytes)
        if pk_u_hash in self.voterMap:
            raise RuntimeError("L'utente ha già votato!")
        print(f"{PRINT_START_AUTHENTICATOR} Authenticator \"{self.name}\" ha verificato che l'utente non abbia già votato controllando la VoterMap.") if verbose else None

        self.tempVote = (c, c_prime, cert_user)

    def bufferingVote(self, verbose: bool = True):
        if self.tempVote is None:
            raise RuntimeError("Nessun voto da bufferizzare.")
        
        c, _, cert_user = self.tempVote

        # Preparazione del messaggio per S
        nonce: bytes = os.urandom(16)
        print(f"{PRINT_START_AUTHENTICATOR} Authenticator \"{self.name}\" genera il nonce: {nonce}") if verbose else None

        # sigma_A = Sign_skA(c || nonce) = Sign_skA(Enc_pkS(v) || nonce)
        data_to_sign: bytes = pack_fields(c, nonce)
        sigma_A = sign(self.sk, data_to_sign)
        print(f"{PRINT_START_AUTHENTICATOR} Authenticator \"{self.name}\" firma il messaggio (c || nonce) ottenendo sigma_A=Sign_skA(c || nonce)") if verbose else None

        pck_to_server: bytes = pack_fields(c, nonce, sigma_A)
        print(f"{PRINT_START_AUTHENTICATOR} Authenticator \"{self.name}\" è pronto il messaggio da inviare al Server: (c || nonce || sigma_A)") if verbose else None

        # bufferizzazione del messaggio da inviare al Server
        self.buffer.append((sha256(cert_user.getPublicKeyBytes()), pck_to_server))
        print(f"{PRINT_START_AUTHENTICATOR} Authenticator \"{self.name}\" bufferizza il messaggio da inviare al Server nella mappa buffer: [H(pk_U) -> (c || nonce || sigma_A)]") if verbose else None

    def sendPckToServer(self, verbose: bool = True) -> bytes:
        """ Estrae un messaggio dal buffer e lo restituisce per inviarlo al Server """
        if len(self.buffer) == 0:
            raise RuntimeError("Nessun messaggio da inviare al Server.")

        # Estrazione casuale di un messaggio dal buffer
        pk_u_hash, pck_to_server = self.buffer.pop(random.randint(0, len(self.buffer) - 1))
        print(f"{PRINT_START_AUTHENTICATOR} Authenticator \"{self.name}\" estrae un messaggio dal buffer per inviarlo al Server.") if verbose else None

        nonce = unpack_fields(pck_to_server, 3)[1] # Estraggo solo il nonce dal pacchetto da inviare al Server
        self.pendingVote = (pk_u_hash, nonce, self.tempVote[1]) # Salvo il voto in attesa di conferma dal Server (H(pk_U), nonce, c')

        self.tempVote = None

        return pck_to_server
    
    def receiveAckFromServer(self, pck_from_server: bytes, verbose: bool = True):
        unpack_from_server = unpack_fields(pck_from_server, 2)
        c_S, s_S = unpack_from_server[0], unpack_from_server[1]
        print(f"{PRINT_START_AUTHENTICATOR} Authenticator \"{self.name}\" riceve un pacchetto dal Server.") if verbose else None
        
        if not verifySign(self.serverCert.getPublicKey(), c_S, s_S):
            raise RuntimeError("Messaggio potenzialmente manipolato.")
        print(f"{PRINT_START_AUTHENTICATOR} Authenticator \"{self.name}\" verifica correttamente la firma del messaggio ricevuto.") if verbose else None

        decrypted_data = rsa_decrypt(private_key=self.sk, ciphertext=c_S)
        print(f"{PRINT_START_AUTHENTICATOR} Authenticator \"{self.name}\" decifra correttamente il messaggio.") if verbose else None

        message = unpack_fields(decrypted_data, 2)
        ack, nonce = message[0], message[1]
        
        if not ack == b"ACK":
            raise RuntimeError("Il messaggio ricevuto non è un ACK.")
        print(f"{PRINT_START_AUTHENTICATOR} Authenticator \"{self.name}\" ha ricevuto un messaggio di tipo ACK dal Server.") if verbose else None

        if not nonce == self.pendingVote[1]:
            raise RuntimeError("Ack di un altro pacchetto.")
        print(f"{PRINT_START_AUTHENTICATOR} Authenticator \"{self.name}\" ha ricevuto correttamente l'ACK del voto inviato al Server.") if verbose else None

        print(f"{PRINT_START_AUTHENTICATOR} Authenticator \"{self.name}\" conferma il voto e registra nella VoterMap [H(pk_U) -> c'].") if verbose else None
        self.voterMap[self.pendingVote[0]] = self.pendingVote[2]  # pendingvote[0]: hash della chiave dell'utente; pendingvote[2]: voto cifrato dell'utente.
        self.pendingVote = None


    def prepareAckForUser(self, pk, verbose: bool = True) -> List[bytes]:
        print(f"{PRINT_START_AUTHENTICATOR} Authenticator \"{self.name}\" prepara ACK da inviare all'Utente.") if verbose else None
        
        sigma = sign(self.sk, b"ACK")
        print(f"{PRINT_START_AUTHENTICATOR} Authenticator \"{self.name}\" ha firmato correttamente l'ACK.") if verbose else None

        pack = pack_fields(sigma, b"ACK")
        c_final = rsa_encrypt_chunks(public_key=pk, plaintext=pack)
        print(f"{PRINT_START_AUTHENTICATOR} Authenticator \"{self.name}\" ha costruito il messaggio da inviare all'Utente.") if verbose else None

        return c_final
    


    # ========================== Fase verificabilità individuale ==========================
    def receiveCverify(self, C_verify: list[bytes], verbose: bool = True) -> list[bytes]:
        """ Riceve C_verify dall'Utente, lo decifra e restituisce c' per la verifica individuale del voto dalla VoterMap """
        print(f"{PRINT_START_AUTHENTICATOR} Authenticator \"{self.name}\" ha ricevuto C_verify dall'Utente.") if verbose else None

        decrypted_data = rsa_decrypt_chunks(private_key=self.sk, encrypted_chunks=C_verify)
        print(f"{PRINT_START_AUTHENTICATOR} Authenticator \"{self.name}\" ha decifrato correttamente C_verify.") if verbose else None

        s_U, cert_user_bytes, verify_request = unpack_fields(decrypted_data, 3)

        cert_user = Certificate.from_bytes(cert_user_bytes)
        pk_U = cert_user.getPublicKey()

        print(f"{PRINT_START_AUTHENTICATOR} Authenticator \"{self.name}\" verifica la firma del messaggio di Verify Request con la chiave pubblica dell'utente...") if verbose else None
        if not verifySign(public_key=pk_U, message=verify_request, signature=s_U):
            raise RuntimeError("Firma del messaggio di Verify Request non valida.")
        print(f"{PRINT_START_AUTHENTICATOR} Authenticator \"{self.name}\" ha verificato correttamente la firma del messaggio di Verify Request.") if verbose else None

        pk_u_hash = sha256(cert_user.getPublicKeyBytes())
        if pk_u_hash not in self.voterMap:
            print("L'utente non ha votato o il voto non è stato confermato dal Server.") if verbose else None
            return None
        print(f"{PRINT_START_AUTHENTICATOR} Authenticator \"{self.name}\" ha verificato che l'utente abbia votato controllando la VoterMap.") if verbose else None

        c = self.voterMap[pk_u_hash]
        print(f"{PRINT_START_AUTHENTICATOR} Authenticator \"{self.name}\" estrae c=Enc_pkU(v) dalla VoterMap") if verbose else None

        s_prime_A = sign(self.sk, c)
        print(f"{PRINT_START_AUTHENTICATOR} Authenticator \"{self.name}\" firma c con la propria chiave privata ottenendo s'_A=Sign_skA(c)") if verbose else None

        Cresponse:list[bytes] = rsa_encrypt_chunks(pk_U, pack_fields(s_prime_A, c))
        print(f"{PRINT_START_AUTHENTICATOR} Authenticator \"{self.name}\" cifra il messaggio di risposta con la pk_U ottenendo C_response=Enc_pkU(s'_A || c)") if verbose else None

        return Cresponse
