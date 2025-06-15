import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HandshakeDigest {
    /*
     * Constructor -- initialise a digest for SHA-256
     */
    private MessageDigest digest;

    public HandshakeDigest() throws NoSuchAlgorithmException {
        this.digest = MessageDigest.getInstance("SHA-256");
    }

    /*
     * Update digest with input data
     */
    public void update(byte[] input) {
        this.digest.update(input);
    }

    /*
     * Compute final digest
     */
    public byte[] digest() {
        return this.digest.digest();
    }
}