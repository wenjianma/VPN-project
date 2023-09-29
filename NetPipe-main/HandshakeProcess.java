import java.io.FileInputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


public class HandshakeProcess {
    HandshakeDigest my_sign;
    HandshakeDigest peer_sign;
    SessionCipher sessioncipher;
    SessionKey sessionkey;
    Socket socket;
    HandshakeCrypto decrypter;
    HandshakeCrypto encrypter;
    HandshakeCertificate ce_user; HandshakeCertificate ce_ca;HandshakeCertificate ce_peer;
    private static DateTimeFormatter timestamp_version = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public HandshakeProcess(Socket socket_in_method, String userCE, String CACE, String COMKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, CertificateException {
        this.socket = socket_in_method;
        byte[] temp = null;
        try{temp = (new FileInputStream(COMKey)).readAllBytes();}catch(Exception e) {throw e;}
        this.decrypter = new HandshakeCrypto(temp);
        try{this.ce_user = new HandshakeCertificate(new FileInputStream(userCE));}catch(Exception e){throw e;}
        this.encrypter = new HandshakeCrypto(this.ce_user);
        try{this.ce_ca = new HandshakeCertificate(new FileInputStream(CACE));}catch(Exception e){throw e;}
        this.my_sign = new HandshakeDigest();
        this.peer_sign = new HandshakeDigest();
    }
    public void ClientHandshake_Process(Socket Socket_in_method) throws CertificateException, IOException, ClassNotFoundException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        HandshakeCertificate handshakeCertificate;
        HandshakeMessage message1 = new HandshakeMessage(HandshakeMessage.MessageType.CLIENTHELLO);
        Base64.Encoder encoder1 = Base64.getEncoder();
        String temp5 = encoder1.encodeToString(this.ce_user.getBytes());
        message1.putParameter("Certificate", temp5);
        this.my_sign.update(message1.getBytes());
        message1.send(Socket_in_method);
        HandshakeMessage message2 = null;
        try{message2 = message2.recv(Socket_in_method);}
        catch(Exception e){System.out.println("Error about recv!");throw e;}
        if(message2.getType()!=HandshakeMessage.MessageType.SERVERHELLO){
            System.out.println("Error about Message Type"); System.exit(1);
        }
        try{
            Base64.Decoder decoder = Base64.getDecoder();
            byte[] temp3 = decoder.decode(message2.getParameter("Certificate"));
            handshakeCertificate = new HandshakeCertificate(temp3);
        }catch(Exception e){System.out.println("Error about Certificate!");throw e;}
        try{handshakeCertificate.verify(this.ce_ca);} catch(Exception e){System.out.println("Error about Certificate!");throw e;}
        this.ce_peer = handshakeCertificate;
        this.peer_sign.update(message2.getBytes());
        HandshakeMessage message3 = new HandshakeMessage(HandshakeMessage.MessageType.SESSION);
        SessionKey sessionKey = new SessionKey(Integer.valueOf(128));
        this.sessioncipher = new SessionCipher(sessionKey);
        HandshakeCrypto handshakeCrypto = new HandshakeCrypto(handshakeCertificate);
        byte[] temp1 = handshakeCrypto.encrypt(this.sessioncipher.getSessionKey().getKeyBytes());
        Base64.Encoder encoder2 = Base64.getEncoder();
        String temp6 = encoder2.encodeToString(temp1);
        message3.putParameter("SessionKey", temp6);
        byte[] temp2 = handshakeCrypto.encrypt(this.sessioncipher.getIVBytes());
        Base64.Encoder encoder3 = Base64.getEncoder();
        String temp7 = encoder3.encodeToString(temp2);
        message3.putParameter("SessionIV", temp7);
        message3.send(Socket_in_method);
        this.my_sign.update(message3.getBytes());
        HandshakeMessage message4 = null;
        message4 = message4.recv(Socket_in_method);
        if(message4.getType()!=HandshakeMessage.MessageType.SERVERFINISHED){
            System.out.println("Error about Message Type"); System.exit(1);
        }

        //Verify the finish message -> timestamp and signature
        //Verify signature
        HandshakeCrypto handshakeCrypto1 = new HandshakeCrypto(this.ce_peer);
        try{
            Base64.Decoder decoder = Base64.getDecoder();
            byte[] TempA = decoder.decode(message4.getParameter("Signature"));
            byte[] TempB = handshakeCrypto1.decrypt(TempA);
            byte[] TempC = this.peer_sign.digest();
            if(!Arrays.equals(TempB, TempC)){throw new IllegalArgumentException("Error about Signature!");}
        }catch(Exception e){System.out.println("Error about Signature!"); throw e;}

        //verify timestamp
        LocalDateTime localDateTime = LocalDateTime.now();
        try{
            Base64.Decoder decoder = Base64.getDecoder();
            byte[] TempD = decoder.decode(message4.getProperty("TimeStamp"));
            byte[] TempE = handshakeCrypto1.decrypt(TempD);
            LocalDateTime localDateTime1 = LocalDateTime.parse(new String(TempE), timestamp_version);
            if( localDateTime1.isAfter(localDateTime.plusSeconds(1L))){
                System.out.println("Error about TimeStamp!"); System.exit(1);
            }
            if( localDateTime1.isBefore(localDateTime.minusSeconds(1L))){
                System.out.println("Error about TimeStamp!"); System.exit(1);
            }
        }catch(Exception e){System.out.println("Error about the timestamp!");throw e;}

        //Signature & Timestamp
        HandshakeMessage message5 = new HandshakeMessage(HandshakeMessage.MessageType.CLIENTFINISHED);
        byte[] Temp1 = this.decrypter.encrypt(this.my_sign.digest());
        Base64.Encoder Encoder1 = Base64.getEncoder();
        String Temp2 = Encoder1.encodeToString(Temp1);
        message5.putParameter("Signature",Temp2);
        byte[] Temp3 = this.decrypter.encrypt(timestamp_version.format(LocalDateTime.now()).getBytes());
        Base64.Encoder Encoder2 = Base64.getEncoder();
        String Temp4 = Encoder2.encodeToString(Temp3);
        message5.putParameter("TimeStamp", Temp4);

        message5.send(Socket_in_method);
    }
    public void ServerHandshake_Process(Socket Socket_in_method) throws IOException, ClassNotFoundException, CertificateException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        HandshakeCertificate handshakeCertificate = null;
        HandshakeMessage message1 = null;
        message1 = message1.recv(Socket_in_method);
        if(message1.getType()!=HandshakeMessage.MessageType.CLIENTHELLO){System.out.println("Error about Message Type"); System.exit(1);}
        try{
            Base64.Decoder decoder = Base64.getDecoder();
            byte[] temp3 = decoder.decode(message1.getProperty("Certificate"));
            handshakeCertificate = new HandshakeCertificate(temp3);
        }catch(Exception e){System.exit(1);}
        try {
            handshakeCertificate.verify(this.ce_ca);
        }catch(Exception e){System.out.println("Error about Certificate!");throw e;}
        this.ce_peer = handshakeCertificate;
        this.peer_sign.update(message1.getBytes());
        HandshakeMessage message2 = new HandshakeMessage(HandshakeMessage.MessageType.SERVERHELLO);
        Base64.Encoder encoder1 = Base64.getEncoder();
        String temp5 = encoder1.encodeToString(this.ce_user.getBytes());
        message2.putParameter("Certificate", temp5);
        message2.send(Socket_in_method);
        this.my_sign.update(message2.getBytes());
        HandshakeMessage message3 = null;
        try{
            message3 = message3.recv(Socket_in_method);
        } catch(Exception exception){
            System.out.println("Error about recv!");
            throw exception;
        }
        if(message3.getType()!=HandshakeMessage.MessageType.SESSION){
            System.out.println("Error about Message Type"); System.exit(1);
        }

        //GET SessionKey and SessionIV
        byte[] temp1; byte[] temp2;
        try{
            Base64.Decoder decoder = Base64.getDecoder();
            byte[] temp3 = decoder.decode(message3.getProperty("SessionKey"));
            temp1 = this.decrypter.decrypt(temp3);
        }catch(Exception e){System.out.println("Error about decryption of SessionKey!");throw e;}
        try{
            Base64.Decoder decoder = Base64.getDecoder();
            byte[] temp4 = decoder.decode(message3.getProperty("SessionIV"));
            temp2 = this.decrypter.decrypt(temp4);
        }catch(Exception e){System.out.println("Error about decryption of SessionIV!");throw e;}
        this.peer_sign.update(message3.getBytes());
        try{
            this.sessionkey = new SessionKey(temp1);
            this.sessioncipher = new SessionCipher(this.sessionkey,temp2);
        }catch(Exception e){System.out.println("Error about sessionkey and sessioncipher!");throw e;}

        // Signature & Timestamp
        HandshakeMessage message4 = new HandshakeMessage(HandshakeMessage.MessageType.SERVERFINISHED);
        byte[] Temp1 = this.decrypter.encrypt(this.my_sign.digest());
        Base64.Encoder Encoder1 = Base64.getEncoder();
        String Temp2 = Encoder1.encodeToString(Temp1);
        message4.putParameter("Signature",Temp2);
        byte[] Temp3 = this.decrypter.encrypt(timestamp_version.format(LocalDateTime.now()).getBytes());
        Base64.Encoder Encoder2 = Base64.getEncoder();
        String Temp4 = Encoder2.encodeToString(Temp3);
        message4.putParameter("TimeStamp", Temp4);

        message4.send(Socket_in_method);
        HandshakeMessage message5 = message4.recv(Socket_in_method);
        if(message5.getType()!=HandshakeMessage.MessageType.CLIENTFINISHED){
            System.out.println("Error about Message Type"); System.exit(1);
        }
        //verify the finish message -> timestamp and signature

        //Verify signature
        HandshakeCrypto handshakeCrypto1 = new HandshakeCrypto(this.ce_peer);
        try{
            Base64.Decoder decoder = Base64.getDecoder();
            byte[] TempA = decoder.decode(message5.getParameter("Signature"));
            byte[] TempB = handshakeCrypto1.decrypt(TempA);
            byte[] TempC = this.peer_sign.digest();
            if(!Arrays.equals(TempB, TempC)){throw new IllegalArgumentException("Error about Signature!");}
        }catch(Exception e){System.out.println("Error about Signature!"); throw e;}

        //verify timestamp
        LocalDateTime localDateTime = LocalDateTime.now();
        try{
            Base64.Decoder decoder = Base64.getDecoder();
            byte[] TempD = decoder.decode(message5.getProperty("TimeStamp"));
            byte[] TempE = handshakeCrypto1.decrypt(TempD);
            LocalDateTime localDateTime1 = LocalDateTime.parse(new String(TempE), timestamp_version);
            if( localDateTime1.isAfter(localDateTime.plusSeconds(1L)) ){
                System.out.println("Error about TimeStamp!"); System.exit(1);
            }
            if( localDateTime1.isBefore(localDateTime.minusSeconds(1L))){
                System.out.println("Error about TimeStamp!"); System.exit(1);
            }
        }catch(Exception e){System.out.println("Error about the timestamp!");throw e;}

    }
}
