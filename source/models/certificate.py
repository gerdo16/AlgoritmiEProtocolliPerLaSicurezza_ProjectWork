from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import rsa, padding

class Certificate:

    def __init__(self, subject_name, issuer_name, public_key):
        self.subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_name)])
        self.issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)])

        self.cert = (
            x509.CertificateBuilder()
            .subject_name(self.subject)
            .issuer_name(self.issuer)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
        )

        self._signed = False
        print(f"[Certificate] Certificato Unsigned creato per \"{subject_name}\" per la CA \"{issuer_name}\"")



    def getSubject(self):
        return self.subject
    
    def getIssuer(self):
        return self.issuer

    def getPublicKey(self):
        return self.cert.public_key()
    
    def isSigned(self):
        return self._signed

    def setSigned(self, signed: bool):
        self._signed = signed


    def setCertificate(self, signedCert):
        self.cert = signedCert


    def verify(self, ca_cert: "Certificate") -> int:
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
            return 0  # se il certificato non è firmato oppure fallisce la verifica, ritorno 0


    def to_bytes(self) -> bytes: 
        """ TRASFORMA UN CERTIFICATO FIRMATO IN BYTE """
        if not self._signed:
            raise RuntimeError("Solo i certificati firmati possono essere serializzati in DER")
        return self.cert.public_bytes(Encoding.DER)
    

    @classmethod
    def from_bytes(cls, data: bytes) -> "Certificate":
        """ TRASFORMA I BYTE RICEVUTI IN UN CERTIFICATO FIRMATO """
        instance = cls.__new__(cls)
        instance.cert = x509.load_der_x509_certificate(data)
        instance._signed = True

        instance._subject = instance.cert.subject
        return instance
    


    def to_csr_bytes(self, private_key) -> bytes:
        """ TRASFORMA UN CERTIFICATO NON FIRMATO IN BYTE """
        if self._signed:
            raise RuntimeError("Il certificato è già firmato, usa to_bytes()")
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(self.cert.subject_name())
            .sign(private_key, hashes.SHA256())
        )
        return csr.public_bytes(Encoding.DER)
    

    def __str__(self):
        out = f"\n===Certificate===\n"
        out += f" - Subject: {self.subject}\n"
        out += f" - Issuer: {self.issuer}\n"
        out += f" - Public Key: {self.cert.public_key()}\n"
        out += f" - firmato: {self._signed}\n"
        out += "===================\n"
        return out