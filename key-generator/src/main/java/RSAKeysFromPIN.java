import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;

public class RSAKeysFromPIN {
    private final int rsaKeySize = 4096;
    private final int ivSize = 16;
    private String feedbackMessage = "";

    public String getFeedbackMessage() {
        return feedbackMessage;
    }

    private static KeyPair generateRsaKeyPair(int rsaKeySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(rsaKeySize);
        return keyPairGenerator.genKeyPair();
    }

    private byte[] getPinHashSha256(String userPIN) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(userPIN.getBytes(StandardCharsets.UTF_8));
    }

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

    private void saveKeys(byte[] publicKey, byte[] notHashed, byte[]privateKey) throws IOException {
        File file = new File("keys/public_key.txt");
        FileOutputStream fop = new FileOutputStream(file);
        fop.write(publicKey);
        fop.close();

        file = new File("keys/original_key.txt");
        fop = new FileOutputStream(file);
        fop.write(privateKey);
        fop.close();

        file = new File("keys/private_key.txt");
        fop = new FileOutputStream(file);
        fop.write(privateKey);
        fop.close();
    }

    public RSAKeysFromPIN(String userPIN) throws Exception {
        KeyPair keyPair = generateRsaKeyPair(rsaKeySize);
        byte[] publicKey = keyPair.getPublic().getEncoded();
        byte[] privateKey = keyPair.getPrivate().getEncoded();

        byte[] aesKey = getPinHashSha256(userPIN);
        byte[] encodedPrivateKey = encryptPrivateKey(privateKey, aesKey);

        byte[] decodedPrivateKey = decryptPrivateKey(encodedPrivateKey, userPIN);
        if (Arrays.equals(privateKey, decodedPrivateKey)) {
            feedbackMessage = "Keys generated and encrypted successfully";
            saveKeys(publicKey, privateKey, encodedPrivateKey);
        }
        else {
            feedbackMessage = "Private key encryption failed";
        }
    }
}
