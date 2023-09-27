import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;

public class HandshakeCrypto {
	CertificateFactory factory;
	private X509Certificate certificate;
	PrivateKey privateKey;
	PublicKey publicKey;

	/*
	 * Constructor to create an instance for encryption/decryption with a public key.
	 * The public key is given as a X509 certificate.
	 */


	public HandshakeCrypto(HandshakeCertificate handshakeCertificate) throws CertificateException {
		this.factory = CertificateFactory.getInstance("X.509");
		this.certificate = handshakeCertificate.getCertificate();
		this.publicKey = certificate.getPublicKey();
	}

	/*
	 * Constructor to create an instance for encryption/decryption with a private key.
	 * The private key is given as a byte array in PKCS8/DER format.
	 */

	public HandshakeCrypto(byte[] keybytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keybytes);
		this.privateKey = keyFactory.generatePrivate(keySpec);
	}

	/*
	 * Decrypt byte array with the key, return result as a byte array
	 */
    public byte[] decrypt(byte[] ciphertext) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
		Cipher cipher = Cipher.getInstance("RSA");
		if (this.publicKey == null) {
			cipher.init(Cipher.DECRYPT_MODE, this.privateKey);
		}
		else {
			cipher.init(Cipher.DECRYPT_MODE, this.publicKey);
		}
		return cipher.doFinal(ciphertext);
    }

	/*
	 * Encrypt byte array with the key, return result as a byte array
	 */
    public byte [] encrypt(byte[] plaintext) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
		Cipher cipher = Cipher.getInstance("RSA");
		if (this.publicKey == null) {
			cipher.init(Cipher.ENCRYPT_MODE, this.privateKey);
		}
		else {
			cipher.init(Cipher.ENCRYPT_MODE, this.publicKey);
		}
		return cipher.doFinal(plaintext);
    }
}
