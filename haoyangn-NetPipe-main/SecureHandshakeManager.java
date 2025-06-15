import java.io.*;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import javax.crypto.*;

public class SecureHandshakeManager {
    public static HandshakeInfo performClientHandshake(Socket socket, Arguments arguments) throws Exception {
        String usercert = arguments.get("usercert");
        String cacert = arguments.get("cacert");
        String key = arguments.get("key");

        HandshakeCertificate clientCert = new HandshakeCertificate(new FileInputStream(usercert));
        HandshakeMessage clienthello = new HandshakeMessage(HandshakeMessage.MessageType.CLIENTHELLO);
        clienthello.putParameter("Certificate", Base64.getEncoder().encodeToString(clientCert.getBytes()));
        clienthello.send(socket);

        HandshakeMessage serverhello;
        do {
            serverhello = HandshakeMessage.recv(socket);
        } while (serverhello.getType() != HandshakeMessage.MessageType.SERVERHELLO);

        String serverCertString = serverhello.getParameter("Certificate");
        HandshakeCertificate serverCert = new HandshakeCertificate(Base64.getDecoder().decode(serverCertString));
        serverCert.verify(new HandshakeCertificate(new FileInputStream(cacert)));

        SessionKey sessionKey = new SessionKey(16);
        SessionCipher sessionCipher = new SessionCipher(sessionKey);
        byte[] sessionKeyBytes = sessionKey.getKeyBytes();
        byte[] ivBytes = sessionCipher.getIVBytes();

        HandshakeCrypto crypto = new HandshakeCrypto(serverCert);
        HandshakeMessage session = new HandshakeMessage(HandshakeMessage.MessageType.SESSION);
        session.putParameter("SessionKey", Base64.getEncoder().encodeToString(crypto.encrypt(sessionKeyBytes)));
        session.putParameter("SessionIV", Base64.getEncoder().encodeToString(crypto.encrypt(ivBytes)));
        session.send(socket);

        HandshakeMessage serverfinished;
        do {
            serverfinished = HandshakeMessage.recv(socket);
        } while (serverfinished.getType() != HandshakeMessage.MessageType.SERVERFINISHED);

        byte[] serverSig = crypto.decrypt(Base64.getDecoder().decode(serverfinished.getParameter("Signature")));
        byte[] serverTime = crypto.decrypt(Base64.getDecoder().decode(serverfinished.getParameter("TimeStamp")));
        HandshakeDigest digest = new HandshakeDigest();
        digest.update(serverhello.getBytes());
        if (!Arrays.equals(digest.digest(), serverSig)) throw new Exception("Server signature mismatch");

        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        Date serverTimestamp = sdf.parse(new String(serverTime, StandardCharsets.UTF_8));
        if (Math.abs(new Date().getTime() - serverTimestamp.getTime()) > 2000)
            throw new Exception("Server timestamp too far from current time");

        ByteBuffer buffer = ByteBuffer.allocate(clienthello.getBytes().length + session.getBytes().length);
        buffer.put(clienthello.getBytes());
        buffer.put(session.getBytes());
        HandshakeDigest clientDigest = new HandshakeDigest();
        clientDigest.update(buffer.array());

        HandshakeCrypto signer = new HandshakeCrypto(new FileInputStream(key).readAllBytes());
        HandshakeMessage clientfinished = new HandshakeMessage(HandshakeMessage.MessageType.CLIENTFINISHED);
        clientfinished.putParameter("Signature", Base64.getEncoder().encodeToString(signer.encrypt(clientDigest.digest())));
        String now = sdf.format(new Date());
        clientfinished.putParameter("TimeStamp", Base64.getEncoder().encodeToString(signer.encrypt(now.getBytes(StandardCharsets.UTF_8))));
        clientfinished.send(socket);

        HandshakeInfo info = new HandshakeInfo();
        info.sessionCipher = sessionCipher;
        info.secureIn = sessionCipher.openDecryptedInputStream(socket.getInputStream());
        info.secureOut = sessionCipher.openEncryptedOutputStream(socket.getOutputStream());
        return info;
    }

    public static HandshakeInfo performServerHandshake(Socket socket, Arguments arguments) throws Exception {
        String usercert = arguments.get("usercert");
        String cacert = arguments.get("cacert");
        String key = arguments.get("key");

        HandshakeMessage clienthello;
        do {
            clienthello = HandshakeMessage.recv(socket);
        } while (clienthello.getType() != HandshakeMessage.MessageType.CLIENTHELLO);

        String clientCertString = clienthello.getParameter("Certificate");
        HandshakeCertificate clientCert = new HandshakeCertificate(Base64.getDecoder().decode(clientCertString));
        clientCert.verify(new HandshakeCertificate(new FileInputStream(cacert)));

        HandshakeCertificate serverCert = new HandshakeCertificate(new FileInputStream(usercert));
        HandshakeMessage serverhello = new HandshakeMessage(HandshakeMessage.MessageType.SERVERHELLO);
        serverhello.putParameter("Certificate", Base64.getEncoder().encodeToString(serverCert.getBytes()));
        serverhello.send(socket);

        HandshakeMessage session;
        do {
            session = HandshakeMessage.recv(socket);
        } while (session.getType() != HandshakeMessage.MessageType.SESSION);

        HandshakeCrypto decryptor = new HandshakeCrypto(new FileInputStream(key).readAllBytes());
        byte[] sessionKey = decryptor.decrypt(Base64.getDecoder().decode(session.getParameter("SessionKey")));
        byte[] iv = decryptor.decrypt(Base64.getDecoder().decode(session.getParameter("SessionIV")));
        SessionCipher sessionCipher = new SessionCipher(new SessionKey(sessionKey), iv);

        HandshakeDigest digest = new HandshakeDigest();
        digest.update(serverhello.getBytes());
        HandshakeCrypto signer = new HandshakeCrypto(new FileInputStream(key).readAllBytes());
        HandshakeMessage serverfinished = new HandshakeMessage(HandshakeMessage.MessageType.SERVERFINISHED);
        serverfinished.putParameter("Signature", Base64.getEncoder().encodeToString(signer.encrypt(digest.digest())));
        String now = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
        serverfinished.putParameter("TimeStamp", Base64.getEncoder().encodeToString(signer.encrypt(now.getBytes(StandardCharsets.UTF_8))));
        serverfinished.send(socket);

        HandshakeMessage clientfinished;
        do {
            clientfinished = HandshakeMessage.recv(socket);
        } while (clientfinished.getType() != HandshakeMessage.MessageType.CLIENTFINISHED);

        HandshakeCrypto clientCrypto = new HandshakeCrypto(clientCert);
        byte[] clientSig = clientCrypto.decrypt(Base64.getDecoder().decode(clientfinished.getParameter("Signature")));
        byte[] clientTime = clientCrypto.decrypt(Base64.getDecoder().decode(clientfinished.getParameter("TimeStamp")));
        HandshakeDigest clientDigest = new HandshakeDigest();
        clientDigest.update(clienthello.getBytes());
        clientDigest.update(session.getBytes());

        if (!Arrays.equals(clientDigest.digest(), clientSig)) throw new Exception("Client signature mismatch");

        Date clientTimestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").parse(new String(clientTime, StandardCharsets.UTF_8));
        if (Math.abs(new Date().getTime() - clientTimestamp.getTime()) > 2000)
            throw new Exception("Client timestamp too far from current time");

        HandshakeInfo info = new HandshakeInfo();
        info.sessionCipher = sessionCipher;
        info.secureIn = sessionCipher.openDecryptedInputStream(socket.getInputStream());
        info.secureOut = sessionCipher.openEncryptedOutputStream(socket.getOutputStream());
        return info;
    }
}