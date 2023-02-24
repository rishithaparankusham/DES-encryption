import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class DESEncryption {
    public static String encrypt(String plaintext, String key) throws Exception {
        // Generate an initialization vector (IV)
        SecureRandom sr = new SecureRandom();
        byte[] iv = new byte[8];
        sr.nextBytes(iv);
        IvParameterSpec ivps = new IvParameterSpec(iv);

        // Generate a DES key
        KeyGenerator kg = KeyGenerator.getInstance("DES");
        kg.init(new SecureRandom(key.getBytes()));
        SecretKey sk = kg.generateKey();

        // Create a Cipher object and specify DES as the algorithm
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, sk, ivps);

        // Encrypt the plaintext
        byte[] encrypted = cipher.doFinal(plaintext.getBytes());

        // Concatenate the IV and encrypted part
        byte[] encryptedIVAndText = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, encryptedIVAndText, 0, iv.length);
        System.arraycopy(encrypted, 0, encryptedIVAndText, iv.length, encrypted.length);

        // Return the encrypted message
        return encryptedIVAndText;
    }

    public static String decrypt(byte[] encryptedIvText, String key) throws Exception {
        // Extract IV and encrypted part
        int ivSize = 8;
        byte[] iv = new byte[ivSize];
        byte[] encryptedText = new byte[encryptedIvText.length - ivSize];
        System.arraycopy(encryptedIvText, 0, iv, 0, iv.length);
        System.arraycopy(encryptedIvText, ivSize, encryptedText, 0, encryptedText.length);

        // Generate a DES key
        KeyGenerator kg = KeyGenerator.getInstance("DES");
        kg.init(new SecureRandom(key.getBytes()));
        SecretKey sk = kg.generateKey();

        // Create a Cipher object and specify DES as the algorithm
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        IvParameterSpec ivps = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, sk, ivps);

        // Decrypt the message
        byte[] decrypted = cipher.doFinal(encryptedText);

        // Return the decrypted message
        return new String(decrypted);
    }
}