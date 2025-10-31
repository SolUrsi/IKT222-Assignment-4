package IKT222.Assignment4;

import java.io.File;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.PreparedStatement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import freemarker.template.TemplateExceptionHandler;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.util.Base64;
import java.nio.charset.StandardCharsets;

// BCrypt library for password hashing
import org.mindrot.jbcrypt.BCrypt;

@SuppressWarnings("serial")
public class AppServlet extends HttpServlet {

  private static final String CONNECTION_URL = "jdbc:sqlite:db.sqlite3";
  // Updated AUTH_QUERY to select hashed password
  private static final String AUTH_QUERY = "select password from user where username=?";
  private static final String SEARCH_QUERY = "select * from patient where surname like ?";

  // AES cipher parameters
  private static final String SECRET_KEY = "SupastrongKey123";
  private static final String ALGORITHM = "AES";
  private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";

  private final Configuration fm = new Configuration(Configuration.VERSION_2_3_28);
  private Connection database;

  @Override
  public void init() throws ServletException {
    configureTemplateEngine();
    connectToDatabase();
  }

  // Helper to get the key spec
  private static SecretKeySpec getKeySpec() {
    return new SecretKeySpec(SECRET_KEY.getBytes(StandardCharsets.UTF_8), ALGORITHM);
  }

  // Decryption method
  private static String decrypt(String encryptedText) throws Exception {
    if (encryptedText == null || encryptedText.isEmpty()) {
      return null;
    }

    byte[] combined = Base64.getDecoder().decode(encryptedText);
    final int IV_LENGTH = 16;

    if (combined.length < IV_LENGTH) {
      throw new IllegalArgumentException("Encrypted data is too short to contain a valid IV.");
    }

    byte[] iv = new byte[IV_LENGTH];
    System.arraycopy(combined, 0, iv, 0, IV_LENGTH);
    IvParameterSpec ivSpec = new IvParameterSpec(iv);

    int cipherTextLength = combined.length - IV_LENGTH;
    byte[] cipherText = new byte[cipherTextLength];
    System.arraycopy(combined, IV_LENGTH, cipherText, 0, cipherTextLength);

    Cipher cipher = Cipher.getInstance(TRANSFORMATION);
    cipher.init(Cipher.DECRYPT_MODE, getKeySpec(), ivSpec);

    byte[] decryptedBytes = cipher.doFinal(cipherText);
    return new String(decryptedBytes, StandardCharsets.UTF_8);
  }

  private void configureTemplateEngine() throws ServletException {
    try {
      fm.setDirectoryForTemplateLoading(new File("./templates"));
      fm.setDefaultEncoding("UTF-8");
      fm.setTemplateExceptionHandler(TemplateExceptionHandler.HTML_DEBUG_HANDLER);
      fm.setLogTemplateExceptions(false);
      fm.setWrapUncheckedExceptions(true);
    } catch (IOException error) {
      throw new ServletException(error.getMessage());
    }
  }

  private void connectToDatabase() throws ServletException {
    try {
      database = DriverManager.getConnection(CONNECTION_URL);
    } catch (SQLException error) {
      throw new ServletException(error.getMessage());
    }
  }

  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    try {
      Template template = fm.getTemplate("login.html");
      template.process(null, response.getWriter());
      response.setContentType("text/html");
      response.setStatus(HttpServletResponse.SC_OK);
    } catch (TemplateException error) {
      response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    }
  }

  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    // Get form parameters
    String username = request.getParameter("username");
    String password = request.getParameter("password");
    String surname = request.getParameter("surname");

    try {
      if (authenticated(username, password)) {
        // Get search results and merge with template
        Map<String, Object> model = new HashMap<>();
        model.put("records", searchResults(surname));
        Template template = fm.getTemplate("details.html");
        template.process(model, response.getWriter());
      } else {
        Template template = fm.getTemplate("invalid.html");
        template.process(null, response.getWriter());
      }
      response.setContentType("text/html");
      response.setStatus(HttpServletResponse.SC_OK);
    } catch (Exception error) {
      response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    }
  }

  private boolean authenticated(String username, String password) throws SQLException {
    // Prepare the SQL statement with placeholders
    try (PreparedStatement pstmt = database.prepareStatement(AUTH_QUERY)) {

      // Bind the user input to the placeholders
      // Driver handles escaping and treats ' or '1=1-- as literal strings
      pstmt.setString(1, username); // Binds 'username' to the first '?'

      // Execute defined query
      try (ResultSet results = pstmt.executeQuery()) {
        // Check if a user with that username was found
        if (results.next()) {
          // User found, get the stored hashed password
          String storedHash = results.getString("password");

          // Verify the provided password against the stored hash
          // BCrypt.checkpw handles all the salt comparison logic
          return BCrypt.checkpw(password, storedHash);
        } else {
          // No such user found
          return false;
        }
      }
    }
  }

  // Modified to decrypt patient data before returning web page
  private List<Record> searchResults(String surname) throws SQLException {
    List<Record> records = new ArrayList<>();

    // Prepare the SQL statement with a placeholder
    try (PreparedStatement pstmt = database.prepareStatement(SEARCH_QUERY)) {

      // Bind the user input to the placeholder, manually adding wildcards
      // as PreparedStatement only protects user input itself
      pstmt.setString(1, '%' + surname + "%");

      // Execute defined query
      try (ResultSet results = pstmt.executeQuery()) {
        while (results.next()) {
          Record rec = new Record();
          String errorMsg = "DECRYPTION FAILED";

          // Plaintext data
          rec.setSurname(results.getString(2)); 
          rec.setDoctorId(results.getString(6));

          // Retrieve encrypted data
          String encryptedForename = results.getString(3);
          String encryptedAddress = results.getString(4);
          String encryptedBorn = results.getString(5);            
          String encryptedTreatedFor = results.getString(7);

          try {
            // Decrypting and setting sensitive columns
            rec.setForename(decrypt(encryptedForename));
            rec.setAddress(decrypt(encryptedAddress));
            rec.setDateOfBirth(decrypt(encryptedBorn)); 
            rec.setDiagnosis(decrypt(encryptedTreatedFor));
          } catch (Exception e) {
            System.err.println(
                "Decryption failed for a record. Data might be corrupted or key is wrong: " + e.getMessage());
            // Set fields to an error message or null if decryption fails
            rec.setForename(errorMsg);
            rec.setAddress(errorMsg);
            rec.setDateOfBirth(errorMsg);
            rec.setDiagnosis(errorMsg);
          }
          records.add(rec);
        }
      }
    }
    return records;
  }
}
