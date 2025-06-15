import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

public class SessionCipher {

    /*
     * Constructor to create a SessionCipher from a SessionKey. The IV is
     * created automatically.
     */
    private SessionKey sessionKey;
    private byte[] ivbytes = new byte[16];
    private Cipher cipherOut, cipherIn;

    public SessionCipher(SessionKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        this.sessionKey = key;
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(this.ivbytes);
        IvParameterSpec iv = new IvParameterSpec(ivbytes);
        this.cipherOut = Cipher.getInstance("AES/CTR/NoPadding");
        this.cipherOut.init(Cipher.ENCRYPT_MODE, key.getSecretKey(), iv);
        this.cipherIn = Cipher.getInstance("AES/CTR/NoPadding");
        this.cipherIn.init(Cipher.DECRYPT_MODE, key.getSecretKey(), iv);
    }

    /*
     * Constructor to create a SessionCipher from a SessionKey and an IV,
     * given as a byte array.
     */

    public SessionCipher(SessionKey key, byte[] ivbytes) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        this.sessionKey = key;
        this.ivbytes = ivbytes;
        IvParameterSpec iv = new IvParameterSpec(ivbytes);
        this.cipherOut = Cipher.getInstance("AES/CTR/NoPadding");
        this.cipherOut.init(Cipher.ENCRYPT_MODE, key.getSecretKey(), iv );
        this.cipherIn = Cipher.getInstance("AES/CTR/NoPadding");
        this.cipherIn.init(Cipher.DECRYPT_MODE, key.getSecretKey(), iv );
    }

    /*
     * Return the SessionKey
     */
    public SessionKey getSessionKey() {
        return this.sessionKey;
    }

    /*
     * Return the IV as a byte array
     */
    public byte[] getIVBytes() {
        return this.ivbytes;
    }

    /*
     * Attach OutputStream to which encrypted data will be written.
     * Return result as a CipherOutputStream instance.
     */
    public CipherOutputStream openEncryptedOutputStream(OutputStream os) {
        CipherOutputStream cOutputStream = new CipherOutputStream(os, cipherOut);
        return cOutputStream;
    }

    /*
     * Attach InputStream from which decrypted data will be read.
     * Return result as a CipherInputStream instance.
     */

    public CipherInputStream openDecryptedInputStream(InputStream inputstream) {
        CipherInputStream cInputStream = new CipherInputStream(inputstream, cipherIn);
        return cInputStream;
    }
}
