<?php
// Database configuration
$host = "localhost";
$username = "root";
$password = "";
$database = "phantom's gym";

// Error reporting for debugging
error_reporting(E_ALL);
ini_set('display_errors', 1);

try {
    // Create connection
    $conn = new mysqli($host, $username, $password, $database);

    // Check connection
    if ($conn->connect_error) {
        throw new Exception("Connection failed: " . $conn->connect_error);
    }

    // Set charset to ensure proper encoding
    $conn->set_charset("utf8mb4");
} catch (Exception $e) {
    // Log the error (you can modify this to log to a file)
    error_log("Database Connection Error: " . $e->getMessage());
    
    // Display user-friendly error message
    die("Sorry, there was a problem connecting to the database. Please try again later.");
}
?>