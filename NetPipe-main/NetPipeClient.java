import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import java.net.*;
import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

public class NetPipeClient {
    private static String PROGRAMNAME = NetPipeClient.class.getSimpleName();
    private static Arguments arguments;

    /*
     * Usage: explain how to use the program, then exit with failure status
     */
    private static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--host=<hostname>");
        System.err.println(indent + "--port=<portnumber>");
        System.err.println(indent + "--usercert=<filename>");
        System.err.println(indent + "--cacert=<filename>");
        System.err.println(indent + "--key=<filename>");
        System.exit(1);
    }

    /*
     * Parse arguments on command line
     */
    private static void parseArgs(String[] args) {
        arguments = new Arguments();
        arguments.setArgumentSpec("host", "hostname");
        arguments.setArgumentSpec("port", "portnumber");
        arguments.setArgumentSpec("usercert","filename");
        arguments.setArgumentSpec("cacert","filename");
        arguments.setArgumentSpec("key","filename");
        try {
            arguments.loadArguments(args);
        } catch (IllegalArgumentException ex) {
            usage();
        }
    }

    private static void CommunicationProcess(InputStream inputstreaminmethod, OutputStream outputstreaminmethod, Socket socketinmethod) throws CertificateException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        HandshakeProcess process = null;
        try{process = new HandshakeProcess(socketinmethod,arguments.get("usercert"), arguments.get("cacert"), arguments.get("key"));}
        catch(Exception e){System.out.println("Error about reading input!");System.exit(1);}
        try {process.ClientHandshake_Process(socketinmethod);}catch (Exception e){System.exit(1);}
        CipherOutputStream ciphertextoutput = null;CipherInputStream ciphertextinput = null;
        try{
            ciphertextinput = process.sessioncipher.openDecryptedInputStream(socketinmethod.getInputStream());
            ciphertextoutput = process.sessioncipher.openEncryptedOutputStream(socketinmethod.getOutputStream());
        }catch(Exception e){System.out.println("Socket error");System.exit(1);}
        Forwarder.forwardStreams(inputstreaminmethod,outputstreaminmethod,ciphertextinput,ciphertextoutput,socketinmethod);
    }

    /*
     * Main program.
     * Parse arguments on command line, connect to server,
     * and call forwarder to forward data between streams.
     */
    public static void main( String[] args) throws CertificateException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Socket socket = null;
        parseArgs(args);
        String host = arguments.get("host");
        int port = Integer.parseInt(arguments.get("port"));
        try {
            socket = new Socket(host, port);
        } catch (IOException ex) {
            System.err.printf("Can't connect to server at %s:%d\n", host, port);
            System.exit(1);
        }
        CommunicationProcess(System.in, System.out, socket);
    }
}
