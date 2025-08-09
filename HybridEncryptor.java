import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.security.spec.MGF1ParameterSpec;

public final class HybridEncryptor {
    private static final int AES_KEY_BITS = 128;
    private static final int GCM_TAG_BITS = 128;
    private static final int GCM_IV_BYTES = 12;

    private HybridEncryptor() {}

    // Create Encrypted Message
    public static Message createEncryptedMessage(User sender, User receiver, String body) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(AES_KEY_BITS, new SecureRandom());
        SecretKey aesKey = kg.generateKey();

        byte[] iv = new byte[GCM_IV_BYTES];
        new SecureRandom().nextBytes(iv);

        Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
        gcm.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
        byte[] ct = gcm.doFinal(body.getBytes(StandardCharsets.UTF_8));

        String ekB64 = rsaOaepEncrypt(aesKey.getEncoded(), receiver.getPublicKey());
        String ivB64 = Base64.getEncoder().encodeToString(iv);
        String ctB64 = Base64.getEncoder().encodeToString(ct);

        Map<String, String> md = new HashMap<>();
        md.put("type", "ENCRYPTED");
        md.put("enc", "AES/GCM/NoPadding");
        md.put("kenc", "RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        md.put("iv", ivB64);
        md.put("ek", ekB64);
        md.put("from", sender.getId());
        md.put("to", receiver.getId());

        return new Message(sender.getId(), receiver.getId(), ctB64, md);
    }

    // Decrypt Encrypted Message
    public static String decryptEncryptedMessage(Message encryptedMessage, User receiver) throws Exception {
        Map<String, String> md = encryptedMessage.getMetadata();
        String type = md.get("type");
        if (!"ENCRYPTED".equals(type) && !"SEALED".equals(type)) {
            throw new IllegalArgumentException("Message is not of type ENCRYPTED or SEALED");
        }

        byte[] aesKeyBytes = rsaOaepDecrypt(md.get("ek"), receiver.getPrivateKey());
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

        byte[] iv = Base64.getDecoder().decode(md.get("iv"));
        byte[] ct = Base64.getDecoder().decode(encryptedMessage.getBody());

        Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
        gcm.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
        byte[] pt = gcm.doFinal(ct);

        return new String(pt, StandardCharsets.UTF_8);
    }

    // RSA Encrypt AES Key
    private static String rsaOaepEncrypt(byte[] data, PublicKey pub) throws Exception {
        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        OAEPParameterSpec oaep = new OAEPParameterSpec(
                "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
        rsa.init(Cipher.ENCRYPT_MODE, pub, oaep);
        return Base64.getEncoder().encodeToString(rsa.doFinal(data));
    }

    // RSA Decrypt AES Key
    private static byte[] rsaOaepDecrypt(String base64, PrivateKey priv) throws Exception {
        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        OAEPParameterSpec oaep = new OAEPParameterSpec(
                "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
        rsa.init(Cipher.DECRYPT_MODE, priv, oaep);
        return rsa.doFinal(Base64.getDecoder().decode(base64));
    }
}
