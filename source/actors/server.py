from actors.certificationauthority import CertificationAuthority
from models.certificate import Certificate
from crypto.asymmetric import *
from crypto.utils import *
from actors.constants import PRINT_START_SERVER, SERVER_COLOR, RESET_COLOR


class Server:
    def __init__(self, name, address, verbose: bool = True):
        self.name = name
        self.address = address
        self.sk, self.pk = None, None
        self.cert: "Certificate" = None
        self.ca: "CertificationAuthority" = None
        self.caAuthenticator: "Certificate" = None

        self.nonceList: set[bytes] = set() # Lista dei nonce generati dall'Authenticator per evitare replay attack

        self.voteDatabase: dict[str, int] = {"SI": 0, "NO": 0} # Database dei voti ricevuti dal Server: (#SI, #NO)
        print(f"{PRINT_START_SERVER} Server \"{self.name}\" creato con address \"{self.address}\"") if verbose else None



    def setCertificationAuthority(self, ca: "CertificationAuthority"):
        self.ca = ca

    def setCAAuthenticatorCertificate(self, cert: "Certificate"):
        self.caAuthenticator = cert

    def getCertificate(self):
        return self.cert



    # ========================== Fase preliminare del sistema ==========================

    def generateKeyPair(self, verbose: bool = True):
        self.sk, self.pk = generate_rsa_key_pair()
        print(f"{PRINT_START_SERVER} Server \"{self.name}\" genera la propria Chiave privata e pubblica") if verbose else None


    def generateUnsignedCertificate(self, verbose: bool = True):
        if self.ca is None:
            raise RuntimeError("Il server non ha una CA assegnata!")
        
        if self.pk is None:
            raise RuntimeError("Il server non ha generato le chiavi!")

        if self.cert is not None:
            print(f"{PRINT_START_SERVER} Server \"{self.name}\" ha già un certificato unsigned!") if verbose else None
            return

        issuer_name = self.ca.getName()
        subject_name = self.name
        self.cert = Certificate(subject_name, issuer_name, self.pk, verbose)
        print(f"{PRINT_START_SERVER} Server \"{self.name}\" genera certificato unsigned per la CA \"{issuer_name}\"") if verbose else None


    def signCertificateWithCA(self, verbose: bool = True):
        if self.ca is None:
            raise RuntimeError("Il server non ha una CA assegnata!")
        
        if self.cert is None:
            raise RuntimeError("Il server non ha un certificato da firmare!")

        print(f"{PRINT_START_SERVER} Server \"{self.name}\" chiede alla CA \"{self.ca.getName()}\" di firmare il suo certificato...") if verbose else None
        self.cert = self.ca.sign(self.cert, verbose)

    
    def verifyCertificate(self, cert: "Certificate", verbose: bool = True) -> bool:
        """ Verifica che il certificato sia stato firmato dalla CA di fiducia del server """
        if self.ca is None:
            raise RuntimeError("Il server non ha una CA assegnata!")
        
        if cert is None:
            raise RuntimeError("Il certificato da verificare è None!")

        print(f"{PRINT_START_SERVER} Server \"{self.name}\" verifica che il certificato di \"{cert.getSubject()}\" sia stato firmato dalla CA \"{self.ca.getName()}\"...") if verbose else None
        return cert.verify(self.ca.getCertificate())



    def receivePckFromAuthenticator(self, pck_from_authenticator: bytes, verbose: bool = True) -> bytes:
        """ Riceve un pacchetto cifrato dall'Authenticator contenente il voto dell'utente """
        print(f"{PRINT_START_SERVER} Server \"{self.name}\" riceve il pacchetto dall'Authenticator contenente il voto dell'utente -> (c || nonce || sigma_A)") if verbose else None

        c, nonce, sigma_A = unpack_fields(pck_from_authenticator, 3)

        print(f"{PRINT_START_SERVER} Server \"{self.name}\" verifica che il nonce ricevuto dall'Authenticator non sia già stato utilizzato...") if verbose else None
        if nonce in self.nonceList:
            raise RuntimeError("Nonce già utilizzato, possibile replay attack!")
        # self.nonceList.add(nonce) NON ancora
        print(f"{PRINT_START_SERVER} Server \"{self.name}\" ha verificato che il nonce ricevuto dall'Authenticator non è stato ancora utilizzato.") if verbose else None

        print(f"{PRINT_START_SERVER} Server \"{self.name}\" verifica la firma dell'Authenticator sul pacchetto ricevuto...") if verbose else None
        data_to_verify: bytes = pack_fields(c, nonce)
        if not verifySign(self.caAuthenticator.getPublicKey(), data_to_verify, sigma_A):
            raise RuntimeError("Firma dell'Authenticator non valida -> V_pk_A(c || nonce, sigma_A) = 0")
        print(f"{PRINT_START_SERVER} Server \"{self.name}\" ha verificato la firma dell'Authenticator sul pacchetto ricevuto -> V_pk_A(c || nonce, sigma_A) = 1") if verbose else None

        print(f"{PRINT_START_SERVER} Server \"{self.name}\" aggiunge il nonce ricevuto dall'Authenticator alla lista dei nonce utilizzati per evitare replay attack.") if verbose else None
        self.nonceList.add(nonce)

        print(f"{PRINT_START_SERVER} Server \"{self.name}\" estrae il voto v dal messaggio cifrato c e lo memorizza nel database dei voti.") if verbose else None
        v:bytes = rsa_decrypt(self.sk, c)
        v:str = v.decode()
        print(f"{PRINT_START_SERVER} Server \"{self.name}\" ha estratto il voto v = \"{v}\" dal messaggio cifrato c.") if verbose else None

        if v not in self.voteDatabase:
            raise RuntimeError(f"Voto ricevuto non valido: {v}. Voti validi sono solo 'SI' o 'NO'.")
        self.voteDatabase[v] += 1
        print(f"{PRINT_START_SERVER} Server \"{self.name}\" ha registrato il voto v = \"{v}\" nel database dei voti -> {SERVER_COLOR}(#SI = {self.voteDatabase['SI']}, #NO = {self.voteDatabase['NO']}){RESET_COLOR}")

        # prepara l'ACK
        ACK:bytes = b"ACK"
        print(f"{PRINT_START_SERVER} Server \"{self.name}\" prepara un ACK da inviare all'Authenticator per confermare la ricezione e registrazione del voto:") if verbose else None

        data_to_encrypt: bytes = pack_fields(ACK, nonce)
        c_S = rsa_encrypt(self.caAuthenticator.getPublicKey(), data_to_encrypt)
        print(f"{PRINT_START_SERVER} Server \"{self.name}\" cifra l'ACK e il nonce con la chiave pubblica dell'Authenticator ottenendo c_S = Enc_pk_A(ACK || nonce)") if verbose else None

        s_S = sign(self.sk, c_S)
        print(f"{PRINT_START_SERVER} Server \"{self.name}\" firma il messaggio cifrato c_S con la propria chiave privata ottenendo s_S = Enc_sk_S(c_S)") if verbose else None

        pck_to_authenticator: bytes = pack_fields(c_S, s_S)
        print(f"{PRINT_START_SERVER} Server \"{self.name}\" ha preparato il pacchetto da inviare all'Authenticator contenente il messaggio cifrato e la firma: (c_S || s_S)") if verbose else None

        return pck_to_authenticator


    # pubblicazione dei risultati finali della votazione
    def publishResults(self, verbose: bool = True) -> bytes:
        print(f"{PRINT_START_SERVER} Server \"{self.name}\" pubblica i risultati finali della votazione...") if verbose else None
        tmp:str = SERVER_COLOR + "SI: " + str(self.voteDatabase["SI"]) + " | NO: " + str(self.voteDatabase["NO"]) + RESET_COLOR
        result_bytes:bytes = tmp.encode()

        s_S = sign(self.sk, result_bytes)
        print(f"{PRINT_START_SERVER} Server \"{self.name}\" firma i risultati con la propria chiave privata ottenendo s_S = Enc_sk_S(result)") if verbose else None

        print(f"{PRINT_START_SERVER} Server \"{self.name}\" {result_bytes} con firma s_S = {s_S}") if verbose else None

        result: bytes = pack_fields(result_bytes, s_S)
        return result
