<?php
session_start();

class VotingSystem {
    private $db;

    public function __construct() {
        // Initialize database connection using PDO
        $this->db = new PDO('sqlite:voting_system.db');
        $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->initializeDatabase();
    }

    private function initializeDatabase() {
        // Create tables if they don't exist
        $this->db->exec("CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            email TEXT UNIQUE,
            password TEXT,
            is_admin INTEGER DEFAULT 0
        )");

        $this->db->exec("CREATE TABLE IF NOT EXISTS candidates (
            id INTEGER PRIMARY KEY,
            name TEXT,
            student_number TEXT UNIQUE,
            course TEXT,
            year TEXT,
            department TEXT,
            picture TEXT,
            speech TEXT
        )");
    }

    public function registerUser($username, $email, $password) {
        // Hash the password securely
        $hashedPassword = password_hash($password, PASSWORD_BCRYPT);

        // Prepare and execute SQL statement to insert user
        $stmt = $this->db->prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
        return $stmt->execute([$username, $email, $hashedPassword]);
    }

    public function loginUser($email, $password) {
        // Retrieve user data from database based on email
        $stmt = $this->db->prepare("SELECT * FROM users WHERE email = ?");
        $stmt->execute([$email]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        // Verify password hash
        if ($user && password_verify($password, $user['password'])) {
            // Initialize session variables for user
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['is_admin'] = $user['is_admin'];
            return true;
        }
        return false;
    }

    public function getUser($id) {
        // Retrieve user data based on user ID
        $stmt = $this->db->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->execute([$id]);
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    public function addCandidate($name, $student_number, $course, $year, $department, $picture, $speech) {
        // Prepare and execute SQL statement to add candidate
        $stmt = $this->db->prepare("INSERT INTO candidates (name, student_number, course, year, department, picture, speech) VALUES (?, ?, ?, ?, ?, ?, ?)");
        return $stmt->execute([$name, $student_number, $course, $year, $department, $picture, $speech]);
    }

    public function getCandidates() {
        // Retrieve all candidates from database
        $stmt = $this->db->query("SELECT * FROM candidates");
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
}

$votingSystem = new VotingSystem();

// Handle POST requests for user registration, login, and candidate addition
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['register'])) {
        // Handle user registration
        $username = $_POST['username'];
        $email = $_POST['email'];
        $password = $_POST['password'];
        $votingSystem->registerUser($username, $email, $password);
        header("Location: index.php");
        exit;
    } elseif (isset($_POST['login'])) {
        // Handle user login
        $email = $_POST['email'];
        $password = $_POST['password'];
        if ($votingSystem->loginUser($email, $password)) {
            header("Location: index.php");
            exit;
        } else {
            echo "Login failed!";
        }
    } elseif (isset($_POST['add_candidate'])) {
        // Handle adding a candidate
        $name = $_POST['name'];
        $student_number = $_POST['student_number'];
        $course = $_POST['course'];
        $year = $_POST['year'];
        $department = $_POST['department'];
        $picture = $_POST['picture'];
        $speech = $_POST['speech'];
        $votingSystem->addCandidate($name, $student_number, $course, $year, $department, $picture, $speech);
        header("Location: index.php");
        exit;
    }
}

// Handle logout
if (isset($_GET['logout'])) {
    session_destroy();
    header("Location: index.php");
    exit;
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Institutional Voting System</title>
</head>
<body>
    <?php if (isset($_SESSION['user_id'])): ?>
        <?php if ($_SESSION['is_admin']): ?>
            <!-- Admin Dashboard -->
            <h1>Admin Dashboard</h1>
            <h2>Add Candidate</h2>
            <form method="POST">
                <input type="text" name="name" placeholder="Name" required>
                <input type="text" name="student_number" placeholder="Student Number" required>
                <input type="text" name="course" placeholder="Course" required>
                <input type="text" name="year" placeholder="Year" required>
                <input type="text" name="department" placeholder="Department" required>
                <input type="text" name="picture" placeholder="Picture URL">
                <textarea name="speech" placeholder="Speech"></textarea>
                <button type="submit" name="add_candidate">Add Candidate</button>
            </form>
            <h2>Users</h2>
            <!-- Admin can manage users here -->
        <?php else: ?>
            <!-- Voter Dashboard -->
            <h1>Voter Dashboard</h1>
            <h2>Candidates</h2>
            <?php foreach ($votingSystem->getCandidates() as $candidate): ?>
                <div>
                    <h3><?php echo htmlspecialchars($candidate['name']); ?></h3>
                    <p><?php echo htmlspecialchars($candidate['speech']); ?></p>
                </div>
            <?php endforeach; ?>
            <!-- Voting functionality goes here -->
        <?php endif; ?>
        <a href="?logout">Logout</a>
    <?php else: ?>
        <!-- Registration and Login Forms -->
        <h1>Register</h1>
        <form method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="email" name="email" placeholder="Email" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit" name="register">Register</button>
        </form>
        <h1>Login</h1>
        <form method="POST">
            <input type="email" name="email" placeholder="Email" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit" name="login">Login</button>
        </form>
    <?php endif; ?>
</body>
</html>
