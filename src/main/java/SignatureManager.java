import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class SignatureManager {
    private final int ivSize = 16;

    private byte[] decryptPrivateKey(byte[] encryptedKeyWithIv, String pin) throws Exception {
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

    private PublicKey getPublicKeyFromBytes(byte[] byteKey) throws Exception {
        PublicKey result = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(byteKey));
        return result;
    }

    private PrivateKey getPrivateKeyFromBytes(byte[] byteKey, String pin) throws Exception {
        byte[] decryptedKey = decryptPrivateKey(byteKey, pin);
        PrivateKey result = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decryptedKey));
        return result;
    }

    public byte[] encryptHash(byte[] hash, byte[] privateKey, String pin) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, getPrivateKeyFromBytes(privateKey, pin));
        byte[] encryptedHash = cipher.doFinal(hash);
        return encryptedHash;
    }

    public byte[] decryptHash(byte[] hash, byte[] publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, getPublicKeyFromBytes(publicKey));
        byte[] decryptedHash = cipher.doFinal(hash);
        return decryptedHash;
    }

    public byte[] createInputHash (byte[] input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] inputHash = md.digest(input);
        return inputHash;
    }

    public SignatureManager() {
    }
}
