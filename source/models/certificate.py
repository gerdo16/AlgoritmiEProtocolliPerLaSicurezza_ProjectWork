from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

class Certificate:

    def __init__(self, subject_name, issuer_name, public_key):
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_name)])
        issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)])

        self.cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
        )

        self.signed = False
        print("certificato creato")


    def getPublicKey(self):
        return self.cert.public_key()
    

    def sign(self, private_key):
        if self.signed:
            print("Certificato già firmato!")
            return
        
        self.cert = self.cert.sign(private_key=private_key, algorithm=hashes.SHA256())
        self.signed = True


    def verify(self, ca_cert: Certificate):
        try:
            cert_bytes = self.cert.tbs_certificate_bytes    # certificato in byte
            sigma = self.cert.signature                     # firma del certificato

            ca_public_key = ca_cert.getPublicKey()
            ca_public_key.verify(
                signature = sigma,
                data = cert_bytes,
                padding = padding.PKCS1v15(),
                algorithm = hashes.SHA256()
            )
            return 1
        except:
            return 0

