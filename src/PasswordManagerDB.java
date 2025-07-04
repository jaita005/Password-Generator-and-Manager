import java.sql.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Base64;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class PasswordManagerDB {
    private static final String ENCRYPTION_KEY = "YourSecretKey123";  // Use a strong secret key
    private static final String ALGORITHM = "AES";

    // Encrypt the password
    public static String encryptPassword(String password) throws Exception {
        Key key = generateKey();
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(password.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    // Decrypt the password
    public static String decryptPassword(String encryptedPassword) throws Exception {
        Key key = generateKey();
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decodedValue = Base64.getDecoder().decode(encryptedPassword);
        byte[] decryptedValue = cipher.doFinal(decodedValue);
        return new String(decryptedValue);
    }

    // Key generation for AES encryption
    private static Key generateKey() throws Exception {
        return new SecretKeySpec(ENCRYPTION_KEY.getBytes(), ALGORITHM);
    }

    // Create the table in MySQL
    public static void createPasswordTable() throws SQLException {
        String query = "CREATE TABLE IF NOT EXISTS passwords (" +
                       "id INT PRIMARY KEY AUTO_INCREMENT, " +
                       "application VARCHAR(255), " +
                       "username VARCHAR(255), " +
                       "password TEXT, " +
                       "expiration_date DATE, " +
                       "encrypted_password TEXT, " +
                       "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)";
        try (Connection conn = DBConnection.getConnection();
             Statement stmt = conn.createStatement()) {
            stmt.execute(query);
        }
    }
    public static String encryptPassword(String password, String salt) {
        String encryptedPassword = null;
        try {
            // Use SHA-256 hashing algorithm
            MessageDigest md = MessageDigest.getInstance("SHA-256");
    
            // Add salt to the hash
            md.update(salt.getBytes());
    
            // Get the hash's bytes and combine with password bytes
            byte[] bytes = md.digest(password.getBytes());
    
            // Convert it into hexadecimal format
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < bytes.length; i++) {
                sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
            }
    
            // Get complete hashed password in hex
            encryptedPassword = sb.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace(); // Handle the exception
        }
    
        return encryptedPassword;
    }


    // Insert a new password record
    public static void insertPassword(String app, String user, String password, Date expirationDate, String salt) throws SQLException {
        // Step 1: Encrypt the password with the salt
        String encryptedPassword = encryptPassword(password, salt);
        
        // Step 2: Modify the query to insert encrypted password and salt
        String query = "INSERT INTO passwords (application, username, password, encrypted_password, expiration_date, salt) VALUES (?, ?, ?, ?, ?, ?)";
        
        // Step 3: Ensure the connection and parameters are correct
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(query)) {
            pstmt.setString(1, app);
            pstmt.setString(2, user);
            pstmt.setString(3, password);  // Plain password (if needed, or can be removed)
            pstmt.setString(4, encryptedPassword);  // Encrypted password
            pstmt.setDate(5, new java.sql.Date(expirationDate.getTime()));
            pstmt.setString(6, salt);  // Salt value
            pstmt.executeUpdate();  // Execute the insert operation
        }
    }
    

    // Get all passwords
    public static ResultSet getAllPasswords() throws SQLException {
        String query = "SELECT application, username, password, expiration_date FROM passwords";
        Connection conn = DBConnection.getConnection();
        Statement stmt = conn.createStatement();
        return stmt.executeQuery(query);
    }

    // Search for password by application or username
    public static ResultSet searchPassword(String searchTerm) throws SQLException {
        String query = "SELECT application, username, password, expiration_date FROM passwords WHERE application LIKE ? OR username LIKE ?";
        Connection conn = DBConnection.getConnection();
        PreparedStatement pstmt = conn.prepareStatement(query);
        pstmt.setString(1, "%" + searchTerm + "%");
        pstmt.setString(2, "%" + searchTerm + "%");
        return pstmt.executeQuery();
    }

    // Update an existing password
    public static void updatePassword(String app, String user, String newPassword) throws Exception {
        String encryptedPassword = encryptPassword(newPassword);
        String query = "UPDATE passwords SET password = ?, encrypted_password = ? WHERE application = ? AND username = ?";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(query)) {
            pstmt.setString(1, newPassword);
            pstmt.setString(2, encryptedPassword);
            pstmt.setString(3, app);
            pstmt.setString(4, user);
            pstmt.executeUpdate();
        }
    }
}

