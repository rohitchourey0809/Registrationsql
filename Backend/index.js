const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const mysql = require("mysql");

const app = express();
const port = 5000;

// Create MySQL connection
const db = mysql.createConnection({
  host: "localhost",
  user: "root", // Change this to your MySQL username
  password: "", // Change this to your MySQL password
  database: "registaion-sql", // Change this to your MySQL database name
});

// Connect to MySQL
db.connect((err) => {
  if (err) {
    console.error("Error connecting to MySQL:", err);
    return;
  }
  console.log("Connected to MySQL database");
});

// Middleware
app.use(bodyParser.json());

// Signup route
app.post("/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Check if email already exists
    db.query(
      "SELECT * FROM users WHERE email = ?",
      [email],
      async (err, results) => {
        if (err) {
          console.error("Error checking email:", err);
          return res.status(500).json({ message: "Internal server error" });
        }

        if (results.length > 0) {
          return res.status(400).json({ message: "Email already exists" });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert new user into database
        db.query(
          "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
          [name, email, hashedPassword],
          (err, result) => {
            if (err) {
              console.error("Error during signup:", err);
              return res.status(500).json({ message: "Internal server error" });
            }
            res.status(201).json({ message: "User created successfully" });
          }
        );
      }
    );
  } catch (error) {
    console.error("Error during signup:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Login route
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user by email
    db.query(
      "SELECT * FROM users WHERE email = ?",
      [email],
      async (err, results) => {
        if (err) {
          console.error("Error finding user:", err);
          return res.status(500).json({ message: "Internal server error" });
        }

        if (results.length === 0) {
          return res.status(401).json({ message: "Invalid email or password" });
        }

        // Compare passwords
        const passwordMatch = await bcrypt.compare(
          password,
          results[0].password
        );
        if (!passwordMatch) {
          return res.status(401).json({ message: "Invalid email or password" });
        }

        // Generate JWT token
        const token = jwt.sign({ email: results[0].email }, "your_secret_key", {
          expiresIn: "1h",
        });

        res.status(200).json({ message: "Login successful", token });
      }
    );
  } catch (error) {
    console.error("Error during login:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
