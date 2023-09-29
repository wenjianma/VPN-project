import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HandshakeDigest {
    /*
     * Constructor -- initialise a digest for SHA-256
     */
    public MessageDigest messagedigest;
    public byte[] digest;
    public HandshakeDigest() throws NoSuchAlgorithmException {
           this.messagedigest = MessageDigest.getInstance("SHA-256");
    }
    /*
     * Update digest with input data
     */
    public void update(byte[] input) {
        this.messagedigest.update(input);
    }
    /*
     * Compute final digest
     */
    public byte[] digest() {
        this.digest =  this.messagedigest.digest();
        return this.digest;
    }
};
