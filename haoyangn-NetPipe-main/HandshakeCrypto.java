import javax.crypto.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class HandshakeCrypto {

    private HandshakeCertificate hanshakeCertificate;
    private Key key;

    /*
     * Constructor to create an instance for encryption/decryption with a public key.
     * The public key is given as a X509 certificate.
     */
    public HandshakeCrypto(HandshakeCertificate handshakeCertificate) {
        this.hanshakeCertificate = handshakeCertificate;
        this.key = handshakeCertificate.publickey;
    }

    /*
     * Constructor to create an instance for encryption/decryption with a private key.
     * The private key is given as a byte array in PKCS8/DER format.
     */

    public HandshakeCrypto(byte[] keybytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PKCS8EncodedKeySpec privatekey = new PKCS8EncodedKeySpec(keybytes);
        KeyFactory key = KeyFactory.getInstance("RSA");
        this.key = key.generatePrivate(privatekey);
    }

    /*
     * Decrypt byte array with the key, return result as a byte array
     */
    public byte[] decrypt(byte[] ciphertext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, this.key, new SecureRandom());
        return cipher.doFinal(ciphertext);

    }

    /*
     * Encrypt byte array with the key, return result as a byte array
     */
    public byte [] encrypt(byte[] plaintext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, this.key, new SecureRandom());
        return cipher.doFinal(plaintext);
    }
}