import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import java.util.Base64;

// This class represents a message that can be sent between users in the system.
class Message {
    private final String senderId;  
    private final String receiverId;     
    private final String body;  
    private final Map<String, String> metadata;    

    public Message(String senderId, String receiverId, String body, Map<String, String> metadata) {
        this.senderId = senderId;       
        this.receiverId = receiverId;   
        this.body = body;               
        this.metadata = metadata;       
    }

    public String getSenderId() { return senderId; }
    public String getReceiverId() { return receiverId; }
    public String getBody() { return body; }
    public Map<String, String> getMetadata() { return metadata; }
}

// User class from teammate's code
class User {
    private final String id;
    private final KeyPair keyPair;

    public User(String id) throws Exception {
        this.id = id;
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        this.keyPair = kpg.generateKeyPair();
    }

    public String getId() { return id; }
    public PublicKey getPublicKey() { return keyPair.getPublic(); }
    public PrivateKey getPrivateKey() { return keyPair.getPrivate(); }
}

// Original signature utility from teammate's code
class SignatureUtil {
    public static String sign(String body, PrivateKey privateKey) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(privateKey);
        sig.update(body.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(sig.sign());
    }

    public static boolean verify(String body, String base64Sig, PublicKey publicKey) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(body.getBytes(StandardCharsets.UTF_8));
        return sig.verify(Base64.getDecoder().decode(base64Sig));
    }
}

// Messaging system combining signing and encryption
class MessagingSystem {
    public static Message createSignedMessage(User sender, User receiver, String body) throws Exception {
        Map<String, String> md = new HashMap<>();
        md.put("type", "SIGNED");
        md.put("sigAlg", "SHA256withRSA");
        String signature = SignatureUtil.sign(body, sender.getPrivateKey());
        md.put("signature", signature);
        return new Message(sender.getId(), receiver.getId(), body, md);
    }

    public static boolean verifySignedMessage(Message m, PublicKey senderPublicKey) throws Exception {
        if (!"SIGNED".equals(m.getMetadata().get("type"))) return false;
        String sig = m.getMetadata().get("signature");
        if (sig == null) return false;
        return SignatureUtil.verify(m.getBody(), sig, senderPublicKey);
    }

    public static Message createSignedConfirmation(Message originalMsg, User receiver) throws Exception {
        String responseBody = "Message received and verified.";
        String origSig = originalMsg.getMetadata().get("signature");
        String origHash = sha256Hex(originalMsg.getBody());
        String returnHash = sha256Hex(responseBody);
        String returnSig = SignatureUtil.sign(responseBody, receiver.getPrivateKey());

        Map<String, String> md = new HashMap<>();
        md.put("type", "SIGNED_CONFIRMATION");
        md.put("origSig", origSig);
        md.put("origHash", origHash);
        md.put("returnHash", returnHash);
        md.put("returnSig", returnSig);

        return new Message(receiver.getId(), originalMsg.getSenderId(), responseBody, md);
    }

    // Uses HybridEncryptor for encryption
    public static Message createEncryptedMessage(User sender, User receiver, String body) throws Exception {
        return HybridEncryptor.createEncryptedMessage(sender, receiver, body);
    }

    public static String decryptEncryptedMessage(Message m, User receiver) throws Exception {
        return HybridEncryptor.decryptEncryptedMessage(m, receiver);
    }

    public static Message createSignedAndEncryptedMessage(User sender, User receiver, String body) throws Exception {
        String signature = SignatureUtil.sign(body, sender.getPrivateKey());
        Message enc = HybridEncryptor.createEncryptedMessage(sender, receiver, body);
        Map<String, String> md = new HashMap<>(enc.getMetadata());
        md.put("type", "SEALED");
        md.put("sigAlg", "SHA256withRSA");
        md.put("signature", signature);
        return new Message(enc.getSenderId(), enc.getReceiverId(), enc.getBody(), md);
    }

    public static String decryptAndVerify(Message sealed, User receiver, PublicKey senderPublicKey) throws Exception {
        if (!"SEALED".equals(sealed.getMetadata().get("type"))) {
            throw new IllegalArgumentException("Not SEALED");
        }
        String plaintext = HybridEncryptor.decryptEncryptedMessage(sealed, receiver);
        String sig = sealed.getMetadata().get("signature");
        if (!SignatureUtil.verify(plaintext, sig, senderPublicKey)) {
            throw new SecurityException("Signature verification failed");
        }
        return plaintext;
    }

    private static String sha256Hex(String s) throws Exception {
        MessageDigest d = MessageDigest.getInstance("SHA-256");
        byte[] out = d.digest(s.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder(2 * out.length);
        for (byte b : out) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}

// Main demo
public class MessagingApp {
    public static void main(String[] args) throws Exception {
        User alice = new User("alice");
        User bob   = new User("bob");

        String msg = "meet @ 10:30 near the library";

        // Encrypted only
        Message enc = MessagingSystem.createEncryptedMessage(alice, bob, msg);
        String dec = MessagingSystem.decryptEncryptedMessage(enc, bob);
        System.out.println("Decrypted (ENCRYPTED): " + dec);

        // Signed + Encrypted
        Message sealed = MessagingSystem.createSignedAndEncryptedMessage(alice, bob, msg);
        String dec2 = MessagingSystem.decryptAndVerify(sealed, bob, alice.getPublicKey());
        System.out.println("Decrypted (SEALED): " + dec2);
    }
}
