import javax.naming.NamingException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.InputStream;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;

import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/*
 * HandshakeCertificate class represents X509 certificates exchanged
 * during initial handshake
 */
public class HandshakeCertificate {
    public byte[] bytes;
    public X509Certificate certificate;
    /*
     * Constructor to create a certificate from data read on an input stream.
     * The data is DER-encoded, in binary or Base64 encoding (PEM format).
     */
    HandshakeCertificate(InputStream instream) throws CertificateException {
        CertificateFactory Cert_Fact = CertificateFactory.getInstance("X.509");
        this.certificate = (X509Certificate) Cert_Fact.generateCertificate(instream);
    }

    /*
     * Constructor to create a certificate from its encoded representation
     * given as a byte array
     */
    HandshakeCertificate(byte[] certbytes) throws CertificateException{
        CertificateFactory Cert_Fact = CertificateFactory.getInstance("X.509");
        InputStream input = new ByteArrayInputStream(certbytes);
        this.certificate = (X509Certificate) Cert_Fact.generateCertificate(input);
    }

    /*
     * Return the encoded representation of certificate as a byte array
     */
    public byte[] getBytes() throws CertificateException {
        return this.certificate.getEncoded();
    }

    /*
     * Return the X509 certificate
     */
    public X509Certificate getCertificate() {
        return this.certificate;
    }

    /*
     * Cryptographically validate a certificate.
     * Throw relevant exception if validation fails.
     */
    public void verify(HandshakeCertificate cacert) throws NoSuchProviderException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        X509Certificate CACERT = cacert.getCertificate();
        this.certificate.verify(CACERT.getPublicKey());
    }

    /*
     * Return CN (Common Name) of subject
     */
    public String getCN() {
        X500Principal prin = this.certificate.getSubjectX500Principal();
        try {
            LdapName lname = new LdapName(prin.getName());
            for(Rdn rdn : lname.getRdns()) {
                if(rdn.getType().equalsIgnoreCase("cn")){
                    return rdn.getValue().toString();
                }
            }
            return prin.getName();
        } catch (NamingException ex){
            return prin.getName();
        }
    }

    /*
     * return email address of subject
     */
    public String getEmail() throws CertificateEncodingException {
        X500Principal prin = this.certificate.getSubjectX500Principal();
        try{
            LdapName lname = new LdapName(prin.toString());
            for(Rdn rdn : lname.getRdns()){
                if(rdn.getType().equalsIgnoreCase("emailaddress")){
                    return rdn.getValue().toString();
                }
            }
            return prin.toString();
        }
        catch(NamingException ex){
            return prin.toString();
        }

    }
}
