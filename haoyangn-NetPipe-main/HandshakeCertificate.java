import javax.crypto.SecretKey;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.io.ByteArrayInputStream;
import java.io.InputStream;

import java.security.*;

import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/*
 * HandshakeCertificate class represents X509 certificates exchanged
 * during initial handshake
 */
public class HandshakeCertificate {

    public X509Certificate certificate;
    private byte[] bytes;
    private String CN;
    private String Email;
    public PublicKey publickey;

    /*
     * Constructor to create a certificate from data read on an input stream.
     * The data is DER-encoded, in binary or Base64 encoding (PEM format).
     */
    public HandshakeCertificate(InputStream instream) throws CertificateException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        this.certificate = (X509Certificate) certificateFactory.generateCertificate(instream);
        this.bytes = this.certificate.getEncoded();
        this.publickey = this.certificate.getPublicKey();
        String DN = this.certificate.getSubjectDN().getName();
        try {
            LdapName ldapName = new LdapName(DN);
            for (Rdn rdn : ldapName.getRdns()) {
                if (rdn.getType().equals("CN")) {
                    this.CN = rdn.getValue().toString();
                }
                if (rdn.getType().equalsIgnoreCase("EMAILADDRESS")) {
                    this.Email = rdn.getValue().toString();
                }
            }
        } catch (InvalidNameException e) {
            throw new RuntimeException(e);
        }
    }

    /*
     * Constructor to create a certificate from its encoded representation
     * given as a byte array
     */
    public HandshakeCertificate(byte[] certbytes) throws CertificateException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        this.certificate = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(certbytes));
        this.bytes = this.certificate.getEncoded();
        this.publickey = this.certificate.getPublicKey();
        String DN = this.certificate.getSubjectDN().getName();
        try {
            LdapName ldapName = new LdapName(DN);
            for (Rdn rdn : ldapName.getRdns()) {
                if (rdn.getType().equals("CN")) {
                    this.CN = rdn.getValue().toString();
                }
                if (rdn.getType().equalsIgnoreCase("EMAILADDRESS")) {
                    this.Email = rdn.getValue().toString();
                }
            }
        } catch (InvalidNameException e) {
            throw new RuntimeException(e);
        }
    }

    /*
     * Return the encoded representation of certificate as a byte array
     */
    public byte[] getBytes() {
        return this.bytes;
    }

    /*
     * Return the X509 certificate
     */
    public X509Certificate getCertificate() {
        return (X509Certificate) this.certificate;
    }

    /*
     * Cryptographically validate a certificate.
     * Throw relevant exception if validation fails.
     */
    public void verify(HandshakeCertificate cacert) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {
        this.certificate.verify(cacert.publickey);
    }

    /*
     * Return CN (Common Name) of subject
     */
    public String getCN() {
        return this.CN;
    }

    /*
     * return email address of subject
     */
    public String getEmail() {
        return this.Email;
    }
}