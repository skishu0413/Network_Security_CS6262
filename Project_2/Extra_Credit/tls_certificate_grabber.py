from OpenSSL import SSL, crypto
import socket

class TLSCertificateGrabber:
    # The hostname and port you are connecting to.
    def __init__(self, hostname, port):
        self.hostname = hostname
        self.port = port
        self.context = SSL.Context(SSL.TLS_CLIENT_METHOD)
        self.context.set_verify(SSL.VERIFY_NONE, lambda *args: True)

    # This will be an <OpenSSL.SSL.Connection object>
    def connect_and_handshake(self) -> SSL.Connection:
        socket_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            socket_connection.connect((self.hostname, self.port))
            ssl_connetion = SSL.Connection(self.context, socket_connection)
            ssl_connetion.set_tlsext_host_name(self.hostname.encode())
            ssl_connetion.set_connect_state()
            ssl_connetion.do_handshake()
            return ssl_connetion
        except Exception as ex:
            socket_connection.close()
            raise ex
        finally:
            socket_connection.close()
    

    # This will be an <OpenSSL.crypto.X509 object>
    def get_certificate(self, ssl_sock: SSL.Connection) -> crypto.X509:
        certificate = ssl_sock.get_peer_certificate()
        return certificate

    # Format: "YYYYMMDDHHMMSSZ" (ASN.1 GeneralizedTime format)
    def get_validity_start(self, cert: crypto.X509) -> str:
        validaity_start = cert.get_notBefore().decode('utf-8')
        return validaity_start

    # Format: "YYYYMMDDHHMMSSZ" (ASN.1 GeneralizedTime format)
    def get_validity_end(self, cert: crypto.X509) -> str:
        validity_end = cert.get_notAfter().decode('utf-8')
        return validity_end

    # We only want the common name (CN)
    # If the Certificate Authority's Distinguished Name
    # in string format is "/C=US/O=Let's Encrypt/CN=R3",
    # return "R3"
    def get_certificate_authority(self, cert: crypto.X509) -> str:
        cert_authority = cert.get_issuer()
        for key, value in  cert_authority.get_components():
            if key.decode('utf-8') == 'CN':
                return value.decode('utf-8')
        return ''

    # Format: a PEM-encoded string, such as
    # "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkh...QIDAQAB\n-----END PUBLIC KEY-----\n"
    def get_public_key(self, cert: crypto.X509) -> str:
        public_key = crypto.dump_publickey(crypto.FILETYPE_PEM, cert.get_pubkey())
        public_key_string = public_key.decode('utf-8')
        return public_key_string

    # Ensure the function returns the existing values in
    # the original order
    def dump_certificate(self) -> (crypto.X509, str, str, str, str):
        ssl_sock = self.connect_and_handshake()
        cert = self.get_certificate(ssl_sock)
        not_before = self.get_validity_start(cert)
        not_after = self.get_validity_end(cert)
        issuer = self.get_certificate_authority(cert)
        public_key = self.get_public_key(cert)
        return cert, issuer, not_before, not_after, public_key

if __name__ == "__main__":
    grabber = TLSCertificateGrabber("www.google.com", 443)
    cert, issuer, not_before, not_after, public_key = grabber.dump_certificate()
    print("Validity start: ", not_before)
    print("Validity end: ", not_after)
    print("Certificate issuer: ", issuer)
    print("Public key: ", public_key)
