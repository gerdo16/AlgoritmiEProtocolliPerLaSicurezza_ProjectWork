from crypto.asymmetric import *
from models.certificate import Certificate
from actors.certificationauthority import CertificationAuthority
import random
from actors.authenticator import Authenticator
import crypto.utils as utils
from typing import List
from actors.constants import PRINT_START_USER, USER_COLOR, RESET_COLOR

class User:
    def __init__(self, name:str, matriculation_number:str, verbose: bool = True):
        self.name = name
        self.matriculation_number = matriculation_number
        self.sk, self.pk = None, None
        self.cert: "Certificate" = None
        self.ca: "CertificationAuthority" = None
        self.serverCert = None
        self.authenticatorCert = None
        self.vote = None
        print(f"{PRINT_START_USER} Utente \"{self.name}\" creato con matricola \"{self.matriculation_number}\"") if verbose else None

    
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
    def generateKeyPair(self, verbose: bool = True):
        self.sk, self.pk = generate_rsa_key_pair()
        print(f"{PRINT_START_USER} Utente \"{self.name}\" genera la propria Chiave privata e pubblica") if verbose else None


    def generateUnsignedCertificate(self, verbose: bool = True):
        if self.ca is None:
            raise RuntimeError("L'utente non ha una CA assegnata!")
        
        if self.pk is None:
            raise RuntimeError("L'utente non ha generato le chiavi!")

        if self.cert is not None:
            print(f"{PRINT_START_USER} Utente \"{self.name}\" ha già un certificato unsigned!") if verbose else None
            return

        issuer_name = self.ca.getName()
        subject_name = self.matriculation_number
        self.cert = Certificate(subject_name, issuer_name, self.pk, verbose)
        print(f"{PRINT_START_USER} Utente \"{self.name}\" genera certificato unsigned per la CA \"{issuer_name}\"") if verbose else None


    def signCertificateWithCA(self, verbose: bool = True):
        if self.ca is None:
            raise RuntimeError("L'utente non ha una CA assegnata!")
        
        if self.cert is None:
            raise RuntimeError("L'utente non ha un certificato da firmare!")

        print(f"{PRINT_START_USER} Utente \"{self.name}\" richiede firma del certificato alla CA di riferimento: {self.ca.getName()}")
        self.cert = self.ca.sign(self.cert, verbose)



    # ========================== Fase Handshake ==========================
    def voteRequestSend(self, authenticator: "Authenticator", verbose: bool = True):
        print(f"{PRINT_START_USER} Utente \"{self.name}\" trasmette un messaggio di Vote Request all'Autheticator: {authenticator.getName()}") if verbose else None
        
        self.authenticatorCert, self.serverCert = authenticator.voteRequestReceive(self, verbose)
        print(f"{PRINT_START_USER} Utente \"{self.name}\" ha ricevuto il certificato dell'Authenticator e del Server in risposta al messaggio di Vote Request")

        if self.authenticatorCert is None:
            raise RuntimeError("Certificato dell'Authenticator non esistente.")
        if self.serverCert is None:
            raise RuntimeError("Certificato del Server non esistente.")
    

    def verifyCertificates(self, verbose: bool = True):
        print(f"{PRINT_START_USER} Utente \"{self.name}\" verifica il certificato dell'Authenticator con la chiave pubblica della Certification Authority.") if verbose else None

        if self.authenticatorCert.verify(self.ca.getCertificate()) == 0:
            raise RuntimeError("Certificato dell'Authenticator non valido.")
        
        print(f"{PRINT_START_USER} Utente \"{self.name}\" ha validato il certificato dell'Authenticator.") if verbose else None
        print(f"{PRINT_START_USER} Utente \"{self.name}\" verifica il certificato del Server con la chiave pubblica della Certification Authority.") if verbose else None

        if self.serverCert.verify(self.ca.getCertificate()) == 0:
            raise RuntimeError("Certificato del Server non valido.")

        print(f"{PRINT_START_USER} Utente \"{self.name}\" ha validato il certificato del Server.") if verbose else None



    # ========================== Fase Trasmissione voto ==========================
    def createCfinal(self, verbose: bool = True) -> list[bytes]:
        """ C_final = Enc_{pk_A}(s || c || c' || Cert(U)) """

        self.vote = random.choice(["SI", "NO"]) # Voto dell'utente, scelto casualmente per la simulazione
        print(f"{PRINT_START_USER} Utente \"{self.name}\" ha scelto il voto: {USER_COLOR}{self.vote}{RESET_COLOR}")

        pk_S = self.serverCert.getPublicKey()
        pk_A = self.authenticatorCert.getPublicKey()

        # Cifratura interna -> c = Enc_{pk_S}(v)
        c:bytes = rsa_encrypt(pk_S, self.vote.encode())
        print(f"{PRINT_START_USER} Utente \"{self.name}\" usa la pk_S per cifrare il voto ottenendo c=Enc_pkS(v)") if verbose else None

        # Firma del cifrato -> sigma = Enc_{sk_U}(c)
        sigma:bytes = sign(self.sk, c)
        print(f"{PRINT_START_USER} Utente \"{self.name}\" usa la propria chiave privata per firmare c ottenendo sigma=Sign_skU(c)") if verbose else None

        # Seconda cifratura voto -> c' = Enc_{pk_U}(v)
        c_prime:bytes = rsa_encrypt(self.pk, self.vote.encode())
        print(f"{PRINT_START_USER} Utente \"{self.name}\" usa la pk_U per cifrare il voto ottenendo c'=Enc_pkU(v)") if verbose else None

        # Cifratura esterna -> C_final = Enc_{pk_A}(s || c || c' || Cert(U))
        cert_u_bytes:bytes = self.cert.to_bytes()
        data_concatenated:bytes = utils.pack_fields(sigma, c, c_prime, cert_u_bytes)
        C_final_chunks: list[bytes] = rsa_encrypt_chunks(pk_A, data_concatenated)

        print(f"{PRINT_START_USER} Utente \"{self.name}\" usa la pk_A per cifrare i dati ottenendo C_final=Enc_pkA(s || c || c' || Cert(U))") if verbose else None

        return C_final_chunks


    def receiveAckFromAuthenticator(self, msg: List[bytes], verbose: bool = True):
        print(f"{PRINT_START_USER} Utente \"{self.name}\" ha ricevuto un messaggio dall'Authenticator.") if verbose else None

        decrypted_msg = rsa_decrypt_chunks(private_key=self.sk, encrypted_chunks=msg)
        print(f"{PRINT_START_USER} Utente \"{self.name}\" ha decifrato il messaggio ricevuto dall'Authenticator.") if verbose else None

        unpacked_msg = utils.unpack_fields(decrypted_msg, 2)
        sigma, ack = unpacked_msg[0], unpacked_msg[1]

        if not verifySign(public_key=self.authenticatorCert.getPublicKey(), message=ack, signature=sigma):
            raise RuntimeError("Firma non valida.")
        print(f"{PRINT_START_USER} Utente \"{self.name}\" ha verificato correttamente la firma del messaggio.") if verbose else None
        print(f"{PRINT_START_USER} Utente \"{self.name}\" ha concluso la sua votazione correttamente, conscio che il suo voto sia stato registrato.") if verbose else None



    # ========================== Fase verificabilità individuale ==========================
    def createCverify(self, verbose: bool = True) -> list[bytes]: 
        """ C_verify = Enc_{pk_A}(s_U || Cert(U) || VerifyRequest), s_U= Sign_{sk_U}(VerifyRequest) """

        verify_request:bytes = b"VerifyRequest"
        print(f"{PRINT_START_USER} Utente \"{self.name}\" crea un messaggio di Verify Request per verificare che il suo voto sia stato conteggiato correttamente.") if verbose else None

        s_U:bytes = sign(self.sk, verify_request)
        print(f"{PRINT_START_USER} Utente \"{self.name}\" firma il messaggio di Verify Request con la propria chiave privata ottenendo s_U=Sign_skU(VerifyRequest)") if verbose else None

        cert_u_bytes:bytes = self.cert.to_bytes()

        data_concatenated:bytes = utils.pack_fields(s_U, cert_u_bytes, verify_request)
        print(f"{PRINT_START_USER} Utente \"{self.name}\" concatena i dati da inviare all'Authenticator: (s_U || Cert(U) || VerifyRequest)") if verbose else None

        C_verify_chunks: list[bytes] = rsa_encrypt_chunks(self.authenticatorCert.getPublicKey(), data_concatenated)
        print(f"{PRINT_START_USER} Utente \"{self.name}\" cifra i dati concatenati con la pk_A ottenendo C_verify=Enc_pkA(s_U || Cert(U) || VerifyRequest)") if verbose else None

        return C_verify_chunks

    def finalizeIndividualVerification(self, c_response_authenticator: list[bytes], verbose: bool = True) -> bool:
        """ L'utente riceve da parte dell'Authenticator il messaggio cifrato con la pk_U contenente c' = Enc_{pk_U}(v) e lo decifra per verificare che il voto v sia stato conteggiato correttamente. """
        print(f"{PRINT_START_USER} Utente \"{self.name}\" riceve da parte dell'Authenticator un messaggio cifrato con la pk_U contenente c' = Enc_pkU(v)") if verbose else None

        data_decrypted: bytes = rsa_decrypt_chunks(self.sk, c_response_authenticator)
        print(f"{PRINT_START_USER} Utente \"{self.name}\" decifra il messaggio ricevuto dall'Authenticator con la propria chiave privata: Dec_skU(C_response)=(s'_A || c)") if verbose else None

        s_prime_A, c = utils.unpack_fields(data_decrypted, 2) # in cui c=Enc_{pk_U}(v)
        print(f"{PRINT_START_USER} Utente \"{self.name}\" estrae i campi dal messaggio decifrato ottenendo s'_A e c=Enc_pkU(v)") if verbose else None

        print(f"{PRINT_START_USER} Utente \"{self.name}\" verifica la firma s'_A con la pk_A dell'Authenticator per assicurarsi che il messaggio provenga effettivamente dall'Authenticator.") if verbose else None
        if not verifySign(public_key=self.authenticatorCert.getPublicKey(), message=c, signature=s_prime_A):
            raise RuntimeError("Firma non valida")
        print(f"{PRINT_START_USER} Utente \"{self.name}\" ha verificato correttamente la firma dell'Authenticator.") if verbose else None

        print(f"{PRINT_START_USER} Utente \"{self.name}\" decifra il voto v dal messaggio c=Enc_pkU(v) usando la propria chiave privata.") if verbose else None
        v_decoded: bytes = rsa_decrypt(self.sk, c)
        v: str = v_decoded.decode()
        print(f"{PRINT_START_USER} Utente \"{self.name}\" ha decifrato il messaggio c=Enc_pkU(v) ottenendo v = \"{v}\"") if verbose else None

        individual_verification_result: bool = (v == self.vote)

        if individual_verification_result:
            print(f"{PRINT_START_USER} Utente \"{self.name}\" ha verificato che il voto conteggiato dall'Authenticator corrisponde al voto scelto -> {USER_COLOR}v=\"{v}\" corrisponde a v*=\"{self.vote}\"{RESET_COLOR}")
        else:
            print(f"{PRINT_START_USER} Utente \"{self.name}\" ha verificato che il voto conteggiato nel sistema NON corrisponde al voto scelto -> {USER_COLOR}v=\"{v}\" diverso da v*=\"{self.vote}\"{RESET_COLOR}")

        return individual_verification_result


    
    def universalVerification(self, result_package: bytes, verbose: bool = True):
        result_bytes, s_S = utils.unpack_fields(result_package, 2)
        print(f"{PRINT_START_USER} Utente \"{self.name}\" estrae i campi dal pacchetto dei risultati pubblicati dal Server ottenendo result e s_S") if verbose else None
        print(f"{PRINT_START_USER} Utente \"{self.name}\" verifica la firma s_S con la pk_S del Server per assicurarsi che i risultati provengano effettivamente dal Server.") if verbose else None
        if not verifySign(public_key=self.serverCert.getPublicKey(), message=result_bytes, signature=s_S):
            raise RuntimeError("Firma non valida")
        print(f"{PRINT_START_USER} Utente \"{self.name}\" ha verificato correttamente la firma del Server sui risultati pubblicati.")
        


    def __str__(self):
        out = f"\n=================================== User: {self.name} ===================================\n"
        out += f" - Matricola: {self.matriculation_number}\n"
        out += f" - Public Key: {self.pk}\n"
        out += f" - Private Key: è privata non si può vedere :)\n"
        out += f" - Certificato: {self.cert}\n"
        out += f" - CA: {self.ca}\n"
        out += "=================================================================================\n"
        return out
