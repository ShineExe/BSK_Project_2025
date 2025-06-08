import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import java.util.function.Consumer;

/**
 * \ingroup KeyGen
 * \brief Class responsible for RSA keys generation.
 * \details Generates key pair based on the submitted PIN and sends back progress information.
 */
public class RSAKeysFromPIN {
    private final int rsaKeySize = 4096;
    private final int ivSize = 16;
    private String feedbackMessage = "";
    private final Consumer<Integer> progressReporter;

    /**
     * \brief Method returns the final information if the generation process was successful or not.
     */
    public String getFeedbackMessage() {
        return feedbackMessage;
    }

    /**
     * \brief Method updates the reported progress of the key generation process.
     */
    private void reportProgress(int percent) {
        if (progressReporter != null) {
            progressReporter.accept(percent);
        }
    }

    /**
     * \brief Method generates an RSA key pair.
     */
    private static KeyPair generateRsaKeyPair(int rsaKeySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(rsaKeySize);
        return keyPairGenerator.genKeyPair();
    }

    /**
     * \brief Method creates an SHA-256 hash of the submitted PIN.
     */
    private byte[] getPinHashSha256(String userPIN) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(userPIN.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * \brief Method encrypts the generated private key for safe storage.
     * \details Using hash obtained from the submitted PIN, method uses AES algorithm to encrypt the key bytes.
     */
    private byte[] encryptPrivateKey(byte[] privateKey, byte[] aesKey) throws Exception {
        byte[] iv = new byte[ivSize];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(aesKey, "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] encodedPrivateKey = cipher.doFinal(privateKey);

        // Combine IV and encrypted part.
        byte[] encryptedKeyWithIV = new byte[ivSize + encodedPrivateKey.length];
        System.arraycopy(iv, 0, encryptedKeyWithIV, 0, ivSize);
        System.arraycopy(encodedPrivateKey, 0, encryptedKeyWithIV, ivSize, encodedPrivateKey.length);

        return  encryptedKeyWithIV;
    }

    /**
     * \brief Method decrypts the generated private key using the submitted PIN.
     * \details Using the AES algorithm, method decrypts the previously encrypted key bytes
     * to check if the whole process was successful.
     */
    private byte[] decryptPrivateKey(byte[] encryptedKeyWithIv, String pin) throws Exception {
        // separate key and iv
        byte[] iv = new byte[ivSize];
        System.arraycopy(encryptedKeyWithIv, 0, iv, 0, iv.length);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        int keySize = encryptedKeyWithIv.length - ivSize;
        byte[] encryptedKey = new byte[keySize];
        System.arraycopy(encryptedKeyWithIv, ivSize, encryptedKey, 0, keySize);

        byte[] aesKey = getPinHashSha256(pin);
        SecretKeySpec secretKeySpec = new SecretKeySpec(aesKey, "AES");
        Cipher cipherDecrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipherDecrypt.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

        return cipherDecrypt.doFinal(encryptedKey);
    }

    /**
     * \brief Method saves the created keys as text files in 'keys' folder.
     */
    private void saveKeys(byte[] publicKey, byte[] notHashed, byte[]privateKey) throws IOException {
        File file = new File("keys/public_key.txt");
        FileOutputStream fop = new FileOutputStream(file);
        fop.write(publicKey);
        fop.close();

        file = new File("keys/private_key.txt");
        fop = new FileOutputStream(file);
        fop.write(privateKey);
        fop.close();
    }

    /**
     * \brief Class initialization. Creates the key pair with submitted PIN.
     * \details Reports the progress of keys generation and encryption of the private key using the AES algorithm.
     */
    public RSAKeysFromPIN(String userPIN, Consumer<Integer> progressReporter) throws Exception {
        this.progressReporter = progressReporter;

        reportProgress(10);
        KeyPair keyPair = generateRsaKeyPair(rsaKeySize);
        reportProgress(20);
        byte[] publicKey = keyPair.getPublic().getEncoded();
        reportProgress(30);
        byte[] privateKey = keyPair.getPrivate().getEncoded();
        reportProgress(40);

        byte[] aesKey = getPinHashSha256(userPIN);
        reportProgress(50);
        byte[] encodedPrivateKey = encryptPrivateKey(privateKey, aesKey);
        reportProgress(70);

        byte[] decodedPrivateKey = decryptPrivateKey(encodedPrivateKey, userPIN);
        reportProgress(90);
        if (Arrays.equals(privateKey, decodedPrivateKey)) {
            reportProgress(100);
            feedbackMessage = "Keys generated and encrypted successfully";
            saveKeys(publicKey, privateKey, encodedPrivateKey);
        }
        else {
            feedbackMessage = "Private key encryption failed";
        }
    }
}
