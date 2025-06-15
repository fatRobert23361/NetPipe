import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Random;

/*
 * Skeleton code for class SessionKey
 */

class SessionKey {
    private SecretKey key;

    /*
     * Constructor to create a secret key of a given length
     */
    public SessionKey(Integer length) {
        byte[] keybytes = new byte[length];
        Random random = new Random();
        for(byte bytes : keybytes){
            bytes = (byte)(random.nextInt(256)-128);
        }
        key = new SecretKeySpec(keybytes, "AES");
    }

    /*
     * Constructor to create a secret key from key material
     * given as a byte array
     */
    public SessionKey(byte[] keybytes) {
        key = new SecretKeySpec(keybytes, "AES");
    }

    /*
     * Return the secret key
     */
    public SecretKey getSecretKey() {
        return key;
    }

    /*
     * Return the secret key encoded as a byte array
     */
    public byte[] getKeyBytes() {
        return key.getEncoded();
    }
}
