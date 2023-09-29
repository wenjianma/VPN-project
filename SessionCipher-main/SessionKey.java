import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;

/*
 * Skeleton code for class SessionKey
 */

class SessionKey {

    /*
     * Constructor to create a secret key of a given length
     */
    private SecretKey Sec_Key;
    public SessionKey(Integer length) throws NoSuchAlgorithmException {
        KeyGenerator key_Gen = KeyGenerator.getInstance("AES");
        key_Gen.init(length);
        this.Sec_Key = key_Gen.generateKey();
    }

    /*
     * Constructor to create a secret key from key material
     * given as a byte array
     */
    public SessionKey(byte[] keybytes) {
        this.Sec_Key = new SecretKeySpec(keybytes, "AES");
    }

    /*
     * Return the secret key
     */
    public SecretKey getSecretKey() {
        return Sec_Key;
    }

    /*
     * Return the secret key encoded as a byte array
     */
    public byte[] getKeyBytes() {
        return Sec_Key.getEncoded();
    }
}

