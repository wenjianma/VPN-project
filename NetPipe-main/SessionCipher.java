import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;

public class SessionCipher {

    /*
     * Constructor to create a SessionCipher from a SessionKey. The IV is
     * created automatically.
     */
    private byte[] ivbytes;
    private IvParameterSpec ivspec;
    private SessionKey key;
    private Cipher cipher1;
    private Cipher cipher2;
    private CipherOutputStream outstream;
    private CipherInputStream instream;

    public SessionCipher(SessionKey key) {
        ivbytes = new byte[128/8];
        new SecureRandom().nextBytes(ivbytes);
        ivspec = new IvParameterSpec(ivbytes);
        this.key = key;
        try{
            cipher1 = Cipher.getInstance("AES/CTR/NoPadding");
            cipher1.init(Cipher.ENCRYPT_MODE, key.getSecretKey(),ivspec);
            cipher2 = Cipher.getInstance("AES/CTR/NoPadding");
            cipher2.init(Cipher.DECRYPT_MODE, key.getSecretKey(),ivspec);
        }
        catch (Exception e) {e.printStackTrace();}
    }

    /*
     * Constructor to create a SessionCipher from a SessionKey and an IV,
     * given as a byte array.
     */

    public SessionCipher(SessionKey key, byte[] ivbytes) {
        this.ivbytes = ivbytes;
        ivspec = new IvParameterSpec(ivbytes);
        this.key = key;
        try{
            cipher1 = Cipher.getInstance("AES/CTR/NoPadding");
            cipher1.init(Cipher.ENCRYPT_MODE, key.getSecretKey(),ivspec);
            cipher2 = Cipher.getInstance("AES/CTR/NoPadding");
            cipher2.init(Cipher.DECRYPT_MODE, key.getSecretKey(),ivspec);
        }
        catch(Exception e){e.printStackTrace();}
    }

    /*
     * Return the SessionKey
     */
    public SessionKey getSessionKey() {
        return key;
    }

    /*
     * Return the IV as a byte array
     */
    public byte[] getIVBytes() {
        return ivbytes;
    }

    /*
     * Attach OutputStream to which encrypted data will be written.
     * Return result as a CipherOutputStream instance.
     */
    CipherOutputStream openEncryptedOutputStream(OutputStream os) {
        try {
            outstream = new CipherOutputStream(os, cipher1);
        } catch(Exception e){e.printStackTrace();}
        return outstream;
    }

    /*
     * Attach InputStream from which decrypted data will be read.
     * Return result as a CipherInputStream instance.
     */

    CipherInputStream openDecryptedInputStream(InputStream inputstream) {
        try {
            instream = new CipherInputStream(inputstream, cipher2);
        }catch(Exception e) {e.printStackTrace();}
        return instream;
    }
}
