const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const { createClient } = require("@supabase/supabase-js");

dotenv.config();

const app = express();
const port = process.env.PORT || 5002;

// Initialize Supabase client
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_ANON_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

// Add this near the top of your file after creating the Supabase client
supabase.auth.onAuthStateChange((event, session) => {
  console.log("Supabase auth event:", event);
});

app.use(
  cors({
    origin: "https://employee-management-two-xi.vercel.app",
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
  })
);
app.use(bodyParser.json());

// Register Endpoint
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res
      .status(400)
      .json({ error: "Username and password are required" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    // Check if user exists using Supabase
    const { data: existingUser, error: searchError } = await supabase
      .from("users")
      .select("username")
      .eq("username", username)
      .single();

    if (searchError && searchError.code !== "PGRST116") {
      // PGRST116 means no rows returned
      throw searchError;
    }

    if (existingUser) {
      return res.status(400).json({ error: "Username already exists" });
    }

    // Insert new user using Supabase
    const { data: newUser, error: insertError } = await supabase
      .from("users")
      .insert([
        {
          username,
          password: hashedPassword,
        },
      ])
      .select("id, username, created_at")
      .single();

    if (insertError) throw insertError;

    res.status(201).json({
      message: "Registration successful",
      user: {
        id: newUser.id,
        username: newUser.username,
        created_at: newUser.created_at,
      },
    });
  } catch (err) {
    console.error("Registration error details:", {
      message: err.message,
      stack: err.stack,
      code: err.code,
    });
    res.status(500).json({ error: "Internal server error: " + err.message });
  }
});

// Login Endpoint
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    // Get user from Supabase
    const { data: user, error } = await supabase
      .from("users")
      .select("id, username, password")
      .eq("username", username)
      .single();

    if (error) {
      if (error.code === "PGRST116") {
        // No rows returned
        return res.status(400).json({ error: "User not found" });
      }
      throw error;
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: "Invalid password" });
    }

    const token = jwt.sign(
      {
        id: user.id,
        username: user.username,
      },
      process.env.JWT_SECRET || "your-jwt-secret",
      { expiresIn: "1h" }
    );

    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
      },
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Add a basic health check route
app.get("/health", (req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// Add this near your other routes
app.get("/test", (req, res) => {
  res.json({ message: "Server is running" });
});

module.exports = app;
