# Password Generator and Manager

## Overview

**Password Generator and Manager** is a Java desktop application that helps users securely generate, store, and manage passwords for multiple accounts and applications. It provides strong encryption, password strength evaluation, and a user-friendly interface to keep your credentials safe and organized.

## Features

- **Secure Password Generation:** Generate strong, random passwords with customizable options.
- **Password Storage:** Store application/user/password combinations with expiration dates.
- **Encryption:** Passwords are encrypted using AES and SHA-256 hashing with salt before being stored in a MySQL database.
- **Search & Update:** Easily search for and update saved credentials.
- **Password Strength Evaluation:** Get feedback on password strength and enforce strong password usage.
- **Graphical User Interface:** Simple and intuitive Swing-based UI for all interactions.
- **Login System:** Basic login for application access (can be extended for more robust authentication).

## Getting Started

### Prerequisites

- Java Development Kit (JDK 8+)
- MySQL Database server
- (Optional) Visual Studio Code with Java extensions

### Setup

1. **Clone the repository:**
    ```bash
    git clone https://github.com/jaita005/Password-Generator-and-Manager.git
    ```

2. **Configure Database:**
    - Create a MySQL database (e.g., `password_manager`).
    - Update the database connection details in `src/DBConnection.java` to match your setup.
    - The application automatically creates the required `passwords` table on first run.

3. **Build and Run:**
    - Use your IDE or the following commands:
      ```bash
      javac -d bin -sourcepath src src/PasswordManagerGUI.java
      java -cp bin src.PasswordManagerGUI
      ```

### Folder Structure

- `src/` - Java source code
- `lib/` - 3rd party libraries (if any)
- `bin/` - Compiled output

## Usage

1. **Login:** Default login is `admin` / `admin123` (for demonstration; change for production).
2. **Add Password:** Enter application, username, and password, then click "Add Password".
3. **Generate Password:** Use "Generate Password" to create a strong password.
4. **Search:** Enter a keyword to search for saved entries.
5. **Update:** Use the "Update Password" button to change an existing password.
6. **View All:** Click "View All Passwords" to see all stored credentials.

## Security Notes

- Passwords are never stored in plain text—both salted hash and AES encryption are used.
- Update the encryption key in code for production use.
- For enhanced security, further authentication (e.g., multi-user, master password) is recommended.

## Contribution

Pull requests are welcome! For major changes, please open an issue first to discuss what you’d like to change.

## License

This project is licensed under the MIT License.

---
