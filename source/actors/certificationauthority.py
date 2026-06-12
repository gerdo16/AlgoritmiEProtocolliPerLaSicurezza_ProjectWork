from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from crypto.asymmetric import generate_rsa_key_pair
from models.certificate import Certificate


class CertificationAuthority:
    def __init__(self, name, address):
        self.name = name
        self.address = address
        self.sk, self.pk = generate_rsa_key_pair()
        self.cert = None
        print(f"[CertificationAuthority] CA {self.name} creata con chiave privata e pubblica")


    def getName(self):
        return self.name
    
    def getAddress(self):
        return self.address
    
    def getPublicKey(self):
        return self.pk
    


    def autoSignCertificate(self):
        """ Firma il proprio certificato con la propria chiave privata """
        if self.cert is not None:
            print("[CertificationAuthority] CA ha già un certificato firmato!")
            return
        
        print(f"[CertificationAuthority] CA {self.name} genera e firma il proprio certificato (si autocertifica)")
        self.cert = Certificate(self.name, self.address, self.pk)
        signed_cert = self.cert.cert.sign(private_key=self.sk, algorithm=hashes.SHA256())
        self.cert.setCertificate(signed_cert)
        self.cert.setSigned(True)



    def sign(self, cert: "Certificate") -> "Certificate":
        """ Firma il certificato con la chiave privata della CA ! """
        if cert.isSigned():
            print("Certificato già firmato!")
            return
        
        print(f"[CertificationAuthority] CA {self.name} verifica della legittimità del certificato prima della firma...") # OIDC

        print(f"[CertificationAuthority] CA {self.name} firma il certificato per {cert.getSubject()}")
        signed_cert = cert.cert.sign(private_key=self.sk, algorithm=hashes.SHA256())
        cert.setCertificate(signed_cert)
        cert.setSigned(True)

        return cert
    

    def __str__(self):
        out = f"\n=================================== Certification Authority {self.name} ===================================\n"
        out += f" - Address: {self.address}\n"
        out += f" - Public Key: {self.pk}\n"
        out += f" - Private Key: è privata non si può vedere :)\n"
        out += f" - Certificato: {self.cert}\n"
        return out