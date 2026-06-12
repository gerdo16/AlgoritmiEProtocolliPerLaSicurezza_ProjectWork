from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
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

        self._signed = False
        print("certificato creato")


    def getPublicKey(self):
        return self.cert.public_key()
    

    def sign(self, private_key):
        if self._signed:
            print("Certificato già firmato!")
            return
        
        self.cert = self.cert.sign(private_key=private_key, algorithm=hashes.SHA256())
        self._signed = True


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


    """ TRASFORMA UN CERTIFICATO FIRMATO IN BYTE """
    def to_bytes(self) -> bytes: 
        if not self._signed:
            raise RuntimeError("Solo i certificati firmati possono essere serializzati in DER")
        return self.cert.public_bytes(Encoding.DER)
    
    """ TRASFORMA I BYTE RICEVUTI IN UN CERTIFICATO FIRMATO """
    @classmethod
    def from_bytes(cls, data: bytes) -> "Certificate":
        instance = cls.__new__(cls)
        instance.cert = x509.load_der_x509_certificate(data)
        instance._signed = True

        instance._subject = instance.cert.subject
        return instance
    
    """ TRASFORMA UN CERTIFICATO NON FIRMATO IN BYTE """
    def to_csr_bytes(self, private_key) -> bytes:
        if self._signed:
            raise RuntimeError("Il certificato è già firmato, usa to_bytes()")
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(self.cert.subject_name())
            .sign(private_key, hashes.SHA256())
        )
        return csr.public_bytes(Encoding.DER)
    