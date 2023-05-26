package secure;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class Secure {

    private Map<String, String> users;
    private Map<String, String> salts;
    private Map<String, String> resetTokens;
    private Map<String, Long> sessionTokens;

    public Secure() {
        users = new HashMap<>();
        salts = new HashMap<>();
        resetTokens = new HashMap<>();
        sessionTokens = new HashMap<>();
    }

    public void register(String username, String password) {
        if (!users.containsKey(username)) {
            byte[] salt = generateSalt();
            String hashedPassword = hashPassword(password, salt);
            users.put(username, hashedPassword);
            salts.put(username, Base64.getEncoder().encodeToString(salt));
            System.out.println("Registration successful. You can now login.");
        } else {
            System.out.println("Username already exists. Please choose a different username.");
        }
    }

    public void login(String username, String password) {
        if (users.containsKey(username)) {
            String hashedPassword = hashPassword(password, Base64.getDecoder().decode(salts.get(username)));
            if (users.get(username).equals(hashedPassword)) {
                System.out.println("Login successful. Welcome, " + username + "!");
                // Perform any additional actions after successful login
            } else {
                System.out.println("Invalid password. Please try again.");
            }
        } else {
            System.out.println("Username not found. Please register an account.");
        }
    }
    
    public void logout(String sessionToken) {
        if (sessionTokens.containsKey(sessionToken)) {
            sessionTokens.remove(sessionToken);
            System.out.println("Logout successful.");
        } else {
            System.out.println("Invalid session token.");
        }
    }
    
    public void requestPasswordReset(String username) {
        if (users.containsKey(username)) {
            String resetToken = generateResetToken();
            resetTokens.put(resetToken, username);
            System.out.println("Password reset token: " + resetToken);
        } else {
            System.out.println("Username not found.");
        }
    }
    
    public void resetPassword(String resetToken, String newPassword) {
        if (resetTokens.containsKey(resetToken)) {
            String username = resetTokens.get(resetToken);
            byte[] salt = generateSalt();
            String hashedPassword = hashPassword(newPassword, salt);
            users.put(username, hashedPassword);
            resetTokens.remove(resetToken);
            System.out.println("Password reset successful.");
        } else {
            System.out.println("Invalid reset token.");
        }
    }
    
    private String generateSessionToken() {
        return generateToken(32);
    }

    private String generateResetToken() {
        return generateToken(16);
    }
    
   /* private String generateToken(int length) {
        SecureRandom secureRandom = new SecureRandom();
        byte[] tokenBytes = new byte[length];
        secureRandom.nextBytes(tokenBytes);
        return Base64.getEncoder().encodeToString(tokenBytes);
    }*/
    private String generateToken(int length) {
        SecureRandom secureRandom = new SecureRandom();
        byte[] tokenBytes = new byte[length];
        secureRandom.nextBytes(tokenBytes);
        return Base64.getEncoder().encodeToString(tokenBytes);
    }


    private byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }

    private String hashPassword(String password, byte[] salt) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(salt);
            byte[] hashedBytes = md.digest(password.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : hashedBytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error hashing password.", e);
        }
    }

    public static void main(String[] args) {
        Secure authSystem = new Secure();
        Scanner scanner = new Scanner(System.in);

        boolean isRunning = true;
        while (isRunning) {
            System.out.println("Choose an option:");
            System.out.println("1. Register");
            System.out.println("2. Login");
            System.out.println("3. Logout");
            System.out.println("4. Request Password Reset");
            System.out.println("5. Reset Password");
            System.out.println("0. Exit");
            System.out.print("Enter your choice: ");
            int choice = scanner.nextInt();
            scanner.nextLine(); // Consume the newline character

            switch (choice) {
                case 1:
                    System.out.print("Enter username: ");
                    String registerUsername = scanner.nextLine();
                    System.out.print("Enter password: ");
                    String registerPassword = scanner.nextLine();
                    authSystem.register(registerUsername, registerPassword);
                    break;
                case 2:
                    System.out.print("Enter username: ");
                    String loginUsername = scanner.nextLine();
                    System.out.print("Enter password: ");
                    String loginPassword = scanner.nextLine();
                    authSystem.login(loginUsername, loginPassword);
                    break;
                case 3:
                    System.out.println("Enter session token:");
                    String logoutToken = scanner.nextLine();
                    authSystem.logout(logoutToken);
                    break;
                case 4:
                    System.out.println("Enter username:");
                    String resetUsername = scanner.nextLine();
                    authSystem.requestPasswordReset(resetUsername);
                    break;
                case 5:
                    System.out.println("Enter reset token:");
                    String resetToken = scanner.nextLine();
                    System.out.println("Enter new password:");
                    String newPassword = scanner.nextLine();
                    authSystem.resetPassword(resetToken, newPassword);
                    break;
                case 0:
                boolean exit = true;
                    break;

                default:
                    System.out.println("Invalid choice. Please try again.");
            }

            System.out.println();
        }

        scanner.close();
    }
}