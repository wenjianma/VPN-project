import javax.crypto.*;
import java.net.*;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;

public class NetPipeServer {
    private static String PROGRAMNAME = NetPipeServer.class.getSimpleName();
    private static Arguments arguments;

    /*
     * Usage: explain how to use the program, then exit with failure status
     */
    private static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
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

    private static void CommunicationProcess(InputStream inputstreaminmethod, OutputStream outputstreaminmethod, Socket socketinmethod) throws NoSuchPaddingException, IllegalBlockSizeException, CertificateException, IOException, NoSuchAlgorithmException, SignatureException, BadPaddingException, NoSuchProviderException, InvalidKeyException, ClassNotFoundException {
        HandshakeProcess process = null;
        try{process = new HandshakeProcess(socketinmethod, arguments.get("usercert"), arguments.get("cacert"), arguments.get("key"));}
        catch(Exception e){System.out.println("Error about reading input!"); System.exit(1);}
        try{process.ServerHandshake_Process(socketinmethod);} catch(Exception e){System.exit(1);}
        CipherOutputStream ciphertextoutput = null; CipherInputStream ciphertextinput = null;
        try{
            ciphertextinput = process.sessioncipher.openDecryptedInputStream(socketinmethod.getInputStream());
            ciphertextoutput = process.sessioncipher.openEncryptedOutputStream(socketinmethod.getOutputStream());
        }catch(Exception e){System.out.println("Socket error\n");System.exit(1);}
        Forwarder.forwardStreams(inputstreaminmethod,outputstreaminmethod,ciphertextinput,ciphertextoutput,socketinmethod);
    }

    /*
     * Main program.
     * Parse arguments on command line, wait for connection from client,
     * and call switcher to switch data between streams.
     */
    public static void main( String[] args) throws NoSuchPaddingException, IllegalBlockSizeException, CertificateException, IOException, NoSuchAlgorithmException, SignatureException, BadPaddingException, NoSuchProviderException, InvalidKeyException, ClassNotFoundException {
        parseArgs(args);
        ServerSocket serverSocket = null;
        int port = Integer.parseInt(arguments.get("port"));
        try {
            serverSocket = new ServerSocket(port);
        } catch (IOException ex) {
            System.err.printf("Error listening on port %d\n", port);
            System.exit(1);
        }
        Socket socket = null;
        try {
            socket = serverSocket.accept();
        } catch (IOException ex) {
            System.out.printf("Error accepting connection on port %d\n", port);
            System.exit(1);
        }
        CommunicationProcess(System.in, System.out, socket);
    }
}
