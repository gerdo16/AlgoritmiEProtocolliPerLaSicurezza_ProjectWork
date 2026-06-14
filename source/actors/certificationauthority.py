from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from crypto.asymmetric import generate_rsa_key_pair
from model.certificate import Certificate
from actors.constants import PRINT_START_CA


class CertificationAuthority:
    def __init__(self, name, address, verbose: bool = True):
        self.name = name
        self.address = address
        self.sk, self.pk = generate_rsa_key_pair()
        self.cert = None
        print(f"{PRINT_START_CA} CA \"{self.name}\" creata con chiave privata e pubblica") if verbose else None


    def getName(self):
        return self.name
    
    def getAddress(self):
        return self.address
    
    def getPublicKey(self):
        return self.pk
    
    def getCertificate(self):
        return self.cert
    


    def autoSignCertificate(self, verbose: bool = True):
        """ Firma il proprio certificato con la propria chiave privata (si autocertifica) """
        if self.cert is not None:
            print(f"{PRINT_START_CA} CA \"{self.name}\" ha già un certificato firmato!") if verbose else None
            return
        
        print(f"{PRINT_START_CA} CA \"{self.name}\" genera e firma il proprio certificato (si autocertifica)") if verbose else None
        self.cert = Certificate(self.name, self.address, self.pk)
        signed_cert = self.cert.cert.sign(private_key=self.sk, algorithm=hashes.SHA256())
        self.cert.setCertificate(signed_cert)
        self.cert.setSigned(True)



    def sign(self, cert: "Certificate", verbose: bool = True) -> "Certificate":
        """ La CA firma il certificato del Server, Authenticator o User con la propria chiave privata ! """
        if cert.isSigned():
            print(f"{PRINT_START_CA} CA \"{self.name}\" - Certificato già firmato!") if verbose else None
            return
        
        print(f"{PRINT_START_CA} CA \"{self.name}\" verifica della legittimità del certificato prima della firma...") if verbose else None # OIDC

        print(f"{PRINT_START_CA} CA \"{self.name}\" firma il certificato per \"{cert.getSubject()}\"") if verbose else None
        signed_cert = cert.cert.sign(private_key=self.sk, algorithm=hashes.SHA256())
        cert.setCertificate(signed_cert)
        cert.setSigned(True)

        return cert
    

    def __str__(self):
        out = f"\n=========== Certification Authority: \"{self.name}\" ===========\n"
        out += f" - Address: {self.address}\n"
        out += f" - Public Key: {self.pk}\n"
        out += f" - Private Key: è privata non si può vedere :)\n"
        out += f" - Certificato: {self.cert}\n"
        return out
