 <?php
session_start();
include 'db_config.php'; // Include database configuration
// Enable error reporting (disable in production)
 

// Process login form submission
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Sanitize and validate inputs
    $email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);
    $password = $_POST['password'];
    $remember = isset($_POST['remember']) ? 1 : 0;

    // Validate inputs
    if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $_SESSION['login_error'] = "Invalid email format";
        header("Location: login.html");
        exit();
    }

    if (empty($password) || strlen($password) < 8) {
        $_SESSION['login_error'] = "Password must be at least 8 characters";
        header("Location: login.html");
        exit();
    }

    // Check user credentials
    try {
        $stmt = $conn->prepare("SELECT id, name, email, password FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows === 1) {
            $user = $result->fetch_assoc();
            
            // Verify password (must match register.php's password_hash())
            if (password_verify($password, $user['password'])) {
                // Regenerate session ID for security
                session_regenerate_id(true);
                
                // Set session variables
                $_SESSION['user'] = [
                    'id' => $user['id'],
                    'name' => $user['name'],
                    'email' => $user['email'],
                    'logged_in' => true
                ];

                // Handle "Remember Me" functionality
                if ($remember) {
                    $token = bin2hex(random_bytes(32));
                    $expiry = time() + (86400 * 30); // 30 days
                    
                    // Store token in database
                    $update_stmt = $conn->prepare("UPDATE users SET remember_token = ? WHERE id = ?");
                    $update_stmt->bind_param("si", $token, $user['id']);
                    $update_stmt->execute();
                    
                    // Set secure cookie
                    setcookie(
                        'remember_token',
                        $token,
                        [
                            'expires' => $expiry,
                            'path' => '/',
                            'secure' => true,
                            'httponly' => true,
                            'samesite' => 'Strict'
                        ]
                    );
                }

                // Redirect to members area
                header("Location: homepage2.html");
                exit();
            }
        }
        
        // If we reach here, login failed
        $_SESSION['login_error'] = "Invalid email or password";
        header("Location: login.html");
        exit();
        
    } catch (Exception $e) {
        error_log("Login error: " . $e->getMessage());
        $_SESSION['login_error'] = "System error. Please try again.";
        header("Location: login.html");
        exit();
    }
}

// Close connection
$conn->close();
?>