 <?php
// Database configuration
$servername = "localhost";
$username = "root"; // default XAMPP username
$password = ""; // default XAMPP password
$dbname = "phantom's gym"; // change to your database name

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Get form data
$name = $_POST['name'];
$email = $_POST['email'];
$password = $_POST['password'];
$confirm_password = $_POST['confirm-password'];
$terms = isset($_POST['terms']) ? 1 : 0;

// Validate data
$errors = [];

if (empty($name)) {
    $errors[] = "Full name is required";
}

if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $errors[] = "Valid email is required";
}

if (empty($password) || strlen($password) < 8) {
    $errors[] = "Password must be at least 8 characters";
}

if ($password !== $confirm_password) {
    $errors[] = "Passwords do not match";
}

if (!$terms) {
    $errors[] = "You must agree to the terms and conditions";
}

// If no errors, proceed with registration
if (empty($errors)) {
    // Hash the password
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);
    
    // Prepare and bind
    $stmt = $conn->prepare("INSERT INTO users (name, email, password) VALUES (?, ?, ?)");
    $stmt->bind_param("sss", $name, $email, $hashed_password);
    
    if ($stmt->execute()) {
        // Registration successful
        header("Location: homepage2.html");
        exit();
    } else {
        $errors[] = "Error: " . $stmt->error;
    }
    
    $stmt->close();
}

$conn->close();

// If there were errors, display them
if (!empty($errors)) {
    echo '<!DOCTYPE html>
    <html>
    <head>
        <title>Registration Error</title>
        <link rel="stylesheet" href="styles.css">
    </head>
    <body>
        <div class="error-container">
            <h2>Registration Errors:</h2>';
    foreach ($errors as $error) {
        echo "<p class='error-message'>$error</p>";
    }
    echo '<p><a href="register.html" class="back-link">Go back to registration</a></p>
        </div>
    </body>
    </html>';
}
?>