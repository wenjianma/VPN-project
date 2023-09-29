import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class HandshakeCrypto {
	CertificateFactory fac;
	private X509Certificate cert;
	PublicKey pub_key;
	PrivateKey pri_key;
	/*
	 * Constructor to create an instance for encryption/decryption with a public key.
	 * The public key is given as a X509 certificate.
	 */
	public HandshakeCrypto(HandshakeCertificate handshakeCertificate) throws CertificateException {
		this.fac = CertificateFactory.getInstance("X.509");
		this.cert = handshakeCertificate.getCertificate();
		this.pub_key = cert.getPublicKey();
	}

	/*
	 * Constructor to create an instance for encryption/decryption with a private key.
	 * The private key is given as a byte array in PKCS8/DER format.
	 */

	public HandshakeCrypto(byte[] keybytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeyFactory key_fac = KeyFactory.getInstance("RSA");
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keybytes);
		this.pri_key = key_fac.generatePrivate(keySpec);
	}

	/*
	 * Decrypt byte array with the key, return result as a byte array
	 */
    public byte[] decrypt(byte[] ciphertext) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException{
		Cipher cipher = Cipher.getInstance("RSA");
		if(this.pub_key == null){
			cipher.init(Cipher.DECRYPT_MODE, this.pri_key);
		}
		if(this.pri_key == null){
			cipher.init(Cipher.DECRYPT_MODE, this.pub_key);
		}
		return cipher.doFinal(ciphertext);
    }

	/*
	 * Encrypt byte array with the key, return result as a byte array
	 */
    public byte [] encrypt(byte[] plaintext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("RSA");
		if(this.pub_key == null){
			cipher.init(Cipher.ENCRYPT_MODE, this.pri_key);
		}
		if(this.pri_key == null){
			cipher.init(Cipher.ENCRYPT_MODE, this.pub_key);
		}
		return cipher.doFinal(plaintext);
    }
}
