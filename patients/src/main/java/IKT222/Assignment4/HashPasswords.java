package IKT222.Assignment4;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;
import java.util.Map;
import org.mindrot.jbcrypt.BCrypt;

/* 
 * Utility to hash all plaintext passwords in the 'user' table of the database.
 * This will only be run once to hash all password entries in the user table.
 */

public class HashPasswords {
    private static final String CONNECTION_URL = "jdbc:sqlite:db.sqlite3";
    private static final String SELECT_USERS_QUERY = "SELECT username, password FROM user";
    private static final String UPDATE_PASSWORD_QUERY = "UPDATE user SET password = ? WHERE username = ?";

    public static void main(String[] args) {
        System.out.println("Starting password hashing utility...");
        Connection connection = null;
        Statement selectStatement = null;
        PreparedStatement updateStatement = null;
        ResultSet users = null;

        // This map will store username -> plaintext password
        Map<String, String> userPasswords = new HashMap<>();

        try {
            // Connect to the database
            Class.forName("org.sqlite.JDBC");
            connection = DriverManager.getConnection(CONNECTION_URL);
            // Use transactions for batch updates, allows rollback on potential errors
            connection.setAutoCommit(false); 

            System.out.println("Connected to database.");

            // Select all users and their current passwords
            selectStatement = connection.createStatement();
            users = selectStatement.executeQuery(SELECT_USERS_QUERY);

            System.out.println("Fetching users...");
            while (users.next()) {
                String username = users.getString("username");
                String plaintextPassword = users.getString("password");

                // Check if password looks like a hash already
                if (plaintextPassword.startsWith("$2a$")) {
                    System.out.println("Skipping user '" + username + "': password already looks hashed.");
                } else {
                    userPasswords.put(username, plaintextPassword);
                }
            }
            System.out.println("Found " + userPasswords.size() + " users with plaintext passwords.");

            //Hash and update passwords
            if (userPasswords.isEmpty()) {
                System.out.println("No plaintext passwords to update.");
                return;
            }

            updateStatement = connection.prepareStatement(UPDATE_PASSWORD_QUERY);

            int count = 0;
            for (Map.Entry<String, String> entry : userPasswords.entrySet()) {
                String username = entry.getKey();
                String plaintextPassword = entry.getValue();

                // Generate a salt and hash the password (work factor 12: https://github.com/jeremyh/jBCrypt)
                String hashedPassword = BCrypt.hashpw(plaintextPassword, BCrypt.gensalt(12));

                // Set parameters for the update query
                updateStatement.setString(1, hashedPassword);
                updateStatement.setString(2, username);

                // Add to batch
                updateStatement.addBatch();
                count++;

                System.out.println("Queued update for user: " + username);
            }

            // Execute the batch update
            System.out.println("Executing batch update for " + count + " users...");
            int[] updateCounts = updateStatement.executeBatch();
            connection.commit(); // Commit transaction

            System.out.println("Successfully updated " + updateCounts.length + " passwords.");
            System.out.println("Password hashing complete.");

        } catch (SQLException | ClassNotFoundException e) {
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
            try { if (users != null) users.close(); } catch (SQLException e) { /* ignored */ }
            try { if (selectStatement != null) selectStatement.close(); } catch (SQLException e) { /* ignored */ }
            try { if (updateStatement != null) updateStatement.close(); } catch (SQLException e) { /* ignored */ }
            try { if (connection != null) connection.close(); } catch (SQLException e) { /* ignored */ }
            System.out.println("Database connection closed.");
        }
    }
}
