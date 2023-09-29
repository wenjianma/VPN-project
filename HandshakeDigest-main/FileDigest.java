import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.io.IOException;

public class FileDigest {
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        HandshakeDigest hd = new HandshakeDigest();
        String input = args[0];
        FileInputStream fileinputstream = new FileInputStream(input);
        byte[] digested = fileinputstream.readAllBytes();
        hd.update(digested);hd.digest();
        Base64.Encoder encoder = Base64.getEncoder();
        encoder.encodeToString(hd.digest);
        System.out.println(encoder.encodeToString(hd.digest));
    }
}
