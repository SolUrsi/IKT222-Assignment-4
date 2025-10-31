package IKT222.Assignment4;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Base64;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

// Simple class to hold patient data and ID before encryption
class PatientRecord {
    int id;
    String forename;
    String surname;
    String address;

    public PatientRecord(int id, String forename, String surname, String address) {
        this.id = id;
        this.forename = forename;
        this.surname = surname;
        this.address = address;
    }
}

public class EncryptPatients {
    // Do not use hardcoded keys in production systems! This is just for examplification.
    private static final String SECRET_KEY = "SupastrongKey123";
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final String CONNECTION_URL = "jdbc:sqlite:db.sqlite3";

    // SQL queries
    private static final String SELECT_PATIENTS_QUERY = "SELECT id, forename, surname, address FROM patient";
    private static final String UPDATE_PATIENT_QUERY = "UPDATE patient SET forename = ?, surname = ?, address = ? WHERE id = ?";

    private static SecretKeySpec getKeySpec() {
        return new SecretKeySpec(SECRET_KEY.getBytes(StandardCharsets.UTF_8), ALGORITHM);
    }

    public static String encrypt(String plainText) throws Exception {
        if (plainText == null || plainText.isEmpty()) {
            return null;
        }

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, getKeySpec(), ivSpec);

        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        // Prepend the IV to the ciphertext
        byte[] combined = new byte[iv.length + encryptedBytes.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encryptedBytes, 0, combined, iv.length, encryptedBytes.length);

        return Base64.getEncoder().encodeToString(combined);
    }

    public static void main(String[] args) {
        System.out.println("Starting patient data encryption utility...");
        Connection connection = null;
        Statement selectStatement = null;
        PreparedStatement updateStatement = null;
        ResultSet patients = null;

        // Collect patient records to encrypt
        List<PatientRecord> patientsToEncrypt = new ArrayList<>();

        try {
            // Connect to the database (Same as HashPasswords.java)
            Class.forName("org.sqlite.JDBC");
            connection = DriverManager.getConnection(CONNECTION_URL);
            // Use transactions for batch updates, allows rollback on potential errors
            connection.setAutoCommit(false);

            System.out.println("Connected to database.");

            // Select all patients
            selectStatement = connection.createStatement();
            patients = selectStatement.executeQuery(SELECT_PATIENTS_QUERY);

            System.out.println("Fetching patient records...");
            while (patients.next()) {
                int id = patients.getInt("id");
                String forename = patients.getString("forename");

                // Simple check to skip already encrypted records (encrypted data is Base64, so it should contain '=')
                if (forename != null && !forename.contains("=")) {
                    patientsToEncrypt.add(new PatientRecord(
                        id,
                        forename,
                        patients.getString("surname"),
                        patients.getString("address")
                    ));
                }
            }
            System.out.println("Found " + patientsToEncrypt.size() + " patients with plaintext data to encrypt.");

            if (patientsToEncrypt.isEmpty()) {
                System.out.println("No plaintext records to update. Encryption utility exiting.");
                return;
            }

            // Encrypt and prepare batch update
            updateStatement = connection.prepareStatement(UPDATE_PATIENT_QUERY);
            int count = 0;

            for (PatientRecord record : patientsToEncrypt) {
                String encryptedForename = encrypt(record.forename);
                String encryptedSurname = encrypt(record.surname);
                String encryptedAddress = encrypt(record.address);

                updateStatement.setString(1, encryptedForename);
                updateStatement.setString(2, encryptedSurname);
                updateStatement.setString(3, encryptedAddress);
                updateStatement.setInt(4, record.id);
                updateStatement.addBatch();
                count++;
            }

            // Execute the batch update and commit
            System.out.println("Executing batch update for " + count + " records...");
            int[] updateCounts = updateStatement.executeBatch();
            connection.commit();

            System.out.println("Successfully encrypted and updated " + updateCounts.length + " patient records.");

        } catch (Exception e) {
            System.err.println("An error occurred: " + e.getMessage());
            e.printStackTrace();
            if (connection != null) {
                try {
                    System.err.println("Rolling back transaction...");
                    connection.rollback();
                } catch (SQLException ex) {
                    System.err.println("Error during rollback: " + ex.getMessage());
                }
            }
        } finally {
            // Clean up
            try {
                if (patients != null) patients.close();
            } catch (SQLException e) { /* ignored */ }
            try {
                if (selectStatement != null) selectStatement.close();
            } catch (SQLException e) { /* ignored */ }
            try {
                if (updateStatement != null) updateStatement.close();
            } catch (SQLException e) { /* ignored */ }
            try {
                if (connection != null) connection.close();
            } catch (SQLException e) { /* ignored */ }
            System.out.println("Database connection closed.");
        }
    }
}
