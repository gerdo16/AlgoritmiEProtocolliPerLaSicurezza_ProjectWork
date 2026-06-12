from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from crypto.asymmetric import generate_rsa_key_pair
from models.certificate import Certificate


class CertificateAuthority:
    def __init__(self, name):
        self.name = name
        self.sk, self.pk = generate_rsa_key_pair()
        print(f"[CertificateAuthority] CA {self.name} creata con chiave privata e pubblica")


    def getName(self):
        return self.name
    
    def getPublicKey(self):
        return self.pk
    

    def sign(self, cert: "Certificate") -> "Certificate":
        """ Firma il certificato con la chiave privata della CA ! """
        if cert.isSigned():
            print("Certificato già firmato!")
            return
        
        print("[CertificateAuthority] CA verifica della legittimità del certificato prima della firma...") # OIDC

        print(f"[CertificateAuthority] Ca firma del certificato per {cert.getSubject()}")
        signed_cert = cert.cert.sign(private_key=self.sk, algorithm=hashes.SHA256())
        cert.setCertificate(signed_cert)
        cert.setSigned(True)

        return cert
    

    def __str__(self):
        out = f"\n===Certificate Authority {self.name}===\n"
        out += f" - Public Key: {self.pk}\n"
        out += f" - Private Key: è privata non si può vedere :)\n"
        return out