import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * \ingroup MainApp
 * \brief Class responsible for main encryption functions.
 * \details The class manages the loaded keys, decrypts them from their stored form,
 * and manages the needed hashes for the RSA algorithms.
 */
public class KeyManager {
    /** Initial vector size for encrypted private key */
    private final int ivSize = 16;

    /**
     * \brief Method responsible for loading the public key from memory
     * \details The method checks the 'keys' folder for the file created by the key-generator component.
     * The set status informs of the action result.
     */
    public byte[] loadPublicKey(JLabel statusLabel) {
        byte[] publicKey = null;
        statusLabel.setText("PublicKey:loaded");
        try {
            publicKey = Files.readAllBytes(Paths.get("keys/public_key.txt"));
        } catch (NullPointerException | IOException fileException) {
            statusLabel.setText("PublicKey:missing!");
        }
        return publicKey;
    }

    /**
     * \brief Method decrypts the private key with the provided PIN.
     */
    public byte[] decryptPrivateKey(byte[] encryptedKeyWithIv, String pin) throws Exception {
        byte[] iv = new byte[ivSize];
        System.arraycopy(encryptedKeyWithIv, 0, iv, 0, iv.length);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        int keySize = encryptedKeyWithIv.length - ivSize;
        byte[] encryptedKey = new byte[keySize];
        System.arraycopy(encryptedKeyWithIv, ivSize, encryptedKey, 0, keySize);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] aesKey = digest.digest(pin.getBytes(StandardCharsets.UTF_8));
        SecretKeySpec secretKeySpec = new SecretKeySpec(aesKey, "AES");
        Cipher cipherDecrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipherDecrypt.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

        return cipherDecrypt.doFinal(encryptedKey);
    }

    /**
     * \brief Method creates and returns the RSA public key from provided bytes.
     */
    public PublicKey getPublicKeyFromBytes(byte[] byteKey) throws Exception {
        PublicKey result = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(byteKey));
        return result;
    }

    /**
     * \brief Method creates and returns the RSA private key from provided bytes.
     */
    public PrivateKey getPrivateKeyFromBytes(byte[] byteKey) throws Exception {
        PrivateKey result = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(byteKey));
        return result;
    }

    /**
     * \brief Method encrypts the provided bytes, using a private key.
     */
    public byte[] encryptHash(byte[] hash, byte[] privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, getPrivateKeyFromBytes(privateKey));
        byte[] encryptedHash = cipher.doFinal(hash);
        return encryptedHash;
    }

    /**
     * \brief Method decrypts the provided hash bytes, using a public key.
     */
    public byte[] decryptHash(byte[] hash, byte[] publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, getPublicKeyFromBytes(publicKey));
        byte[] decryptedHash = cipher.doFinal(hash);
        return decryptedHash;
    }

    /**
     * \brief Method creates a hash of if the provided input using the SHA-256 algorithm.
     */
    public byte[] getDocumentHash(byte[] input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] inputHash = md.digest(input);
        return inputHash;
    }

    public KeyManager() {
    }
}
