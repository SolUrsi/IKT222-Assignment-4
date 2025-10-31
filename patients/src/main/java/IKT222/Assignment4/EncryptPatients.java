package IKT222.Assignment4;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Base64;
import java.nio.charset.StandardCharsets;

public class EncryptPatients {
    private static final String SECRET_KEY = "Super_duper_secret_key_123!"; 
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final String CONNECTION_URL = "jdbc:sqlite:db.sqlite3";
    private static final String SELECT_USERS_QUERY = "SELECT forename, surname, address FROM patient";
    private static final String UPDATE_USERS_QUERY = "UPDATE patient SET forename = ?, surname = ?, address = ? WHERE id = ?";

    private static SecretKeySpec getKeySpec() {
        return new SecretKeySpec(SECRET_KEY.getBytes(StandardCharsets.UTF_8), ALGORITHM);
    }

    public static String encrypt(String plainText) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        
        // Generate a secure random 16-byte IV for CBC mode
        byte[] iv = new byte[16]; 
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, getKeySpec(), ivSpec);
        
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        
        // Prepend the IV to the ciphertext before Base64 encoding. 
        // Necessary for decryption
        byte[] combined = new byte[iv.length + encryptedBytes.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encryptedBytes, 0, combined, iv.length, encryptedBytes.length);

        // Store or transmit the combined (IV + Ciphertext) Base64-encoded string
        return Base64.getEncoder().encodeToString(combined);
    }

    public static void main(String[] args) {
        System.out.println("Starting patient encryption utility...");
        Connection connection = null;
        Statement selectStatement = null;
        PreparedStatement updateStatement = null;
        ResultSet patients = null;

        
        try () {

        } catch () {

        } finally {
            // Clean up
        }
    }
}
