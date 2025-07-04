import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.sql.*;
import java.util.Date;
import java.util.Random;
import java.util.regex.Pattern;
import java.util.Base64;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;


public class PasswordManagerGUI extends JFrame {
    private JTextField appField, userField, passwordField, searchField;
    private JTable passwordTable;
    private DefaultTableModel tableModel;
    private JPasswordField loginPasswordField;
    private JTextField loginIdField;
    private JPanel loginPanel, mainPanel;

    public PasswordManagerGUI() {
        setTitle("Password Manager and Generator");
        setSize(800, 600);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        initLoginUI();
    }

    // Initialize the login UI
    private void initLoginUI() {
        loginPanel = new JPanel(new GridLayout(3, 2));
        loginIdField = new JTextField();
        loginPasswordField = new JPasswordField();
        JButton loginButton = new JButton("Login");

        loginPanel.add(new JLabel("Login ID:"));
        loginPanel.add(loginIdField);
        loginPanel.add(new JLabel("Password:"));
        loginPanel.add(loginPasswordField);
        loginPanel.add(new JLabel());
        loginPanel.add(loginButton);
        add(loginPanel, BorderLayout.CENTER);

        // Add login action
        loginButton.addActionListener(e -> {
            String loginId = loginIdField.getText();
            String password = new String(loginPasswordField.getPassword());

            // Simple login check (replace with actual authentication logic)
            if (loginId.equals("admin") && password.equals("admin123")) {
                initMainUI();
            } else {
                JOptionPane.showMessageDialog(this, "Invalid Login");
            }
        });
    }

    // Initialize the main UI after login
    private void initMainUI() {
        getContentPane().removeAll();  // Clear login panel
        mainPanel = new JPanel(new BorderLayout());
    
        // North Panel with input fields for adding passwords
        JPanel inputPanel = new JPanel(new GridLayout(5, 2));
        appField = new JTextField();
        userField = new JTextField();
        passwordField = new JTextField();
        JButton addButton = new JButton("Add Password");
        JButton updateButton = new JButton("Update Password"); // New Update Button
    
        inputPanel.add(new JLabel("Application:"));
        inputPanel.add(appField);
        inputPanel.add(new JLabel("Username:"));
        inputPanel.add(userField);
        inputPanel.add(new JLabel("Password:"));
        inputPanel.add(passwordField);
        inputPanel.add(new JLabel());
        inputPanel.add(addButton);
        inputPanel.add(new JLabel());  // Space holder
        inputPanel.add(updateButton);  // Add Update Button to the layout
    
        mainPanel.add(inputPanel, BorderLayout.NORTH);
    
        // Center Panel with the password table
        tableModel = new DefaultTableModel(new String[]{"Application", "Username", "Password", "Expiration Date"}, 0);
        passwordTable = new JTable(tableModel);
        JScrollPane scrollPane = new JScrollPane(passwordTable);
        mainPanel.add(scrollPane, BorderLayout.CENTER);
    
        // South Panel with search and generate password features
        JPanel southPanel = new JPanel();
        searchField = new JTextField(20);
        JButton searchButton = new JButton("Search");
        JButton generateButton = new JButton("Generate Password");
        JButton viewButton = new JButton("View All Passwords");
        southPanel.add(new JLabel("Search:"));
        southPanel.add(searchField);
        southPanel.add(searchButton);
        southPanel.add(generateButton);
        southPanel.add(viewButton);
        mainPanel.add(southPanel, BorderLayout.SOUTH);
    
        // Add action listeners for buttons
        addButton.addActionListener(e -> addPassword());
        searchButton.addActionListener(e -> searchPassword());
        generateButton.addActionListener(e -> generatePassword());
        viewButton.addActionListener(e -> refreshPasswordTable());
    
        // Add action listener for Update Password button
        updateButton.addActionListener(e -> openUpdatePasswordDialog());
    
        add(mainPanel);
        revalidate();
        repaint();
    }
    
    // Method to open the Update Password dialog
    private void openUpdatePasswordDialog() {
        // Create the dialog
        JDialog updateDialog = new JDialog(this, "Update Password", true);
        updateDialog.setSize(400, 300);
        updateDialog.setLocationRelativeTo(this); // Center the dialog
    
        // Create components for the dialog
        JPanel dialogPanel = new JPanel(new GridLayout(4, 2));
        JTextField appField = new JTextField();
        JTextField userField = new JTextField();
        JPasswordField newPasswordField = new JPasswordField();
        JLabel passwordStrengthLabel = new JLabel("Password Strength: ");
        JButton submitUpdateButton = new JButton("Submit");
    
        dialogPanel.add(new JLabel("Application:"));
        dialogPanel.add(appField);
        dialogPanel.add(new JLabel("Username:"));
        dialogPanel.add(userField);
        dialogPanel.add(new JLabel("New Password:"));
        dialogPanel.add(newPasswordField);
        dialogPanel.add(passwordStrengthLabel); // Add the password strength label
        dialogPanel.add(submitUpdateButton);
    
        updateDialog.add(dialogPanel);
        
        // Add action listener for the submit update button
        submitUpdateButton.addActionListener(e -> {
            String app = appField.getText();
            String user = userField.getText();
            String newPassword = new String(newPasswordField.getPassword());
    
            // Check password strength
            String passwordStrength = checkPasswordStrength(newPassword);
            passwordStrengthLabel.setText("Password Strength: " + passwordStrength);
    
            // Update the password if the strength is acceptable
            if (passwordStrength.equals("Strong")) {
                try {
                    updatePassword(app, user, newPassword);
                    JOptionPane.showMessageDialog(this, "Password updated successfully!", "Success", JOptionPane.INFORMATION_MESSAGE);
                    updateDialog.dispose();  // Close the dialog after success
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(this, "Error updating password: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                }
            } else {
                JOptionPane.showMessageDialog(this, "Please enter a stronger password.", "Weak Password", JOptionPane.WARNING_MESSAGE);
            }
        });
    
        updateDialog.setVisible(true);  // Show the dialog
    }
    
    // Method to generate a random salt
    public static String generateSalt(int length) {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder salt = new StringBuilder();
        Random rand = new Random();
        for (int i = 0; i < length; i++) {
            salt.append(chars.charAt(rand.nextInt(chars.length())));
        }
        return salt.toString();
    }

    // Add password to database
    private void addPassword() {
        try {
            String app = appField.getText();
            String user = userField.getText();
            String password = passwordField.getText();
            java.util.Date utilDate = new Date(System.currentTimeMillis() + 30L * 24 * 60 * 60 * 1000);  // 30 days
            java.sql.Date sqlExpirationDate = new java.sql.Date(utilDate.getTime());
            String salt = generateSalt(16);
            PasswordManagerDB.insertPassword(app, user, password, sqlExpirationDate, salt);
            refreshPasswordTable();
            JOptionPane.showMessageDialog(this, "Password added successfully!");
        } 
        catch (SQLException ex) {
            ex.printStackTrace();
            JOptionPane.showMessageDialog(this, "SQL Error: " + ex.getMessage());
        } catch (Exception ex) {
            ex.printStackTrace();
            JOptionPane.showMessageDialog(this, "Error: " + ex.getMessage());
        }
        
    }
    public static String checkPasswordStrength(String password) {
        int passwordStrength = 0;
    
        if (password.length() >= 8) {
            passwordStrength++;
        }
        if (password.matches(".*\\d.*")) {  // Contains at least one digit
            passwordStrength++;
        }
        if (password.matches(".*[a-z].*")) {  // Contains at least one lowercase letter
            passwordStrength++;
        }
        if (password.matches(".*[A-Z].*")) {  // Contains at least one uppercase letter
            passwordStrength++;
        }
        if (password.matches(".*[!@#$%^&*(),.?\":{}|<>].*")) {  // Contains special characters
            passwordStrength++;
        }
    
        // Return strength based on conditions
        if (passwordStrength >= 4) {
            return "Strong";
        } else {
            return "Weak";
        }
    }
    public static String encryptPassword(String password, String salt) {
        try {
            // Combine password and salt
            String saltedPassword = password + salt;
            
            // Create a MessageDigest instance for SHA-256
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            
            // Hash the salted password
            byte[] hashedBytes = md.digest(saltedPassword.getBytes());
            
            // Encode the hash as a Base64 string
            return Base64.getEncoder().encodeToString(hashedBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error encrypting password", e);
        }
    }
    
    
    public static void updatePassword(String app, String user, String newPassword) throws SQLException {
        // Step 1: Check password strength
        String passwordStrength = checkPasswordStrength(newPassword);
        
        // Step 2: Generate a new alphanumeric salt for the new password
        String salt = generateSalt(16);  // Alphanumeric salt with length 16
        
        // Step 3: Encrypt the new password using the existing encryption method
        String encryptedPassword = encryptPassword(newPassword, salt);
        
        // Step 4: SQL query to update the password
        String query = "UPDATE passwords SET password = ?, encrypted_password = ?, salt = ? WHERE application = ? AND username = ?";
        
        // Step 5: Execute the query
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(query)) {
            pstmt.setString(1, newPassword);  // Plain password
            pstmt.setString(2, encryptedPassword);  // Encrypted password
            pstmt.setString(3, salt);  // Salt value
            pstmt.setString(4, app);
            pstmt.setString(5, user);
    
            int rowsAffected = pstmt.executeUpdate();  // Execute update
    
            // Step 6: Notify the user about password strength and success/failure of update
            if (rowsAffected > 0) {
                System.out.println("Password updated successfully! Strength: " + passwordStrength);
            } else {
                System.out.println("Failed to update password. Check if the application and username are correct.");
            }
        }
    }
    
    

    // Search for password
    private void searchPassword() {
        try {
            String searchTerm = searchField.getText();
            ResultSet rs = PasswordManagerDB.searchPassword(searchTerm);
            tableModel.setRowCount(0);  // Clear table
            while (rs.next()) {
                tableModel.addRow(new Object[]{
                    rs.getString("application"),
                    rs.getString("username"),
                    rs.getString("password"),
                    rs.getDate("expiration_date")
                });
            }
        } catch (SQLException ex) {
            ex.printStackTrace();
        }
    }

    // Generate a strong password
    private void generatePassword() {
        String password = generateRandomPassword(12);  // Generate a 12-character password
        passwordField.setText(password);
        String strength = evaluatePasswordStrength(password);
        JOptionPane.showMessageDialog(this, "Generated Password: " + password + "\nStrength: " + strength);
    }

    // Evaluate password strength
    private String evaluatePasswordStrength(String password) {
        if (password.length() >= 12 && Pattern.compile("[^a-zA-Z0-9]").matcher(password).find()) {
            return "Strong";
        } else if (password.length() >= 8) {
            return "Medium";
        } else {
            return "Weak";
        }
    }

    // Refresh the password table with all records from the database
    private void refreshPasswordTable() {
        try {
            ResultSet rs = PasswordManagerDB.getAllPasswords();
            tableModel.setRowCount(0);  // Clear table
            while (rs.next()) {
                tableModel.addRow(new Object[]{
                    rs.getString("application"),
                    rs.getString("username"),
                    rs.getString("password"),
                    rs.getDate("expiration_date")
                });
            }
        } catch (SQLException ex) {
            ex.printStackTrace();
        }
    }

    // Generate a random password
    private String generateRandomPassword(int length) {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";
        StringBuilder password = new StringBuilder();
        Random rand = new Random();
        for (int i = 0; i < length; i++) {
            password.append(chars.charAt(rand.nextInt(chars.length())));
        }
        return password.toString();
    }

    public static void main(String[] args) {
        try {
            PasswordManagerDB.createPasswordTable();  // Ensure the table is created
        } catch (SQLException e) {
            e.printStackTrace();
        }
        SwingUtilities.invokeLater(() -> new PasswordManagerGUI().setVisible(true));
    }
}
