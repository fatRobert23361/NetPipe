import java.io.InputStream;
import java.io.OutputStream;

public class HandshakeInfo {
    public SessionKey sessionKey;
    public SessionCipher sessionCipher;
    public InputStream secureIn;
    public OutputStream secureOut;
}