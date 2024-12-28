const bcrypt = require("bcrypt");
const UserModel = require("../model/User.model");
const { generateToken } = require("../jwt.util");
const { creationGuard } = require("../middleware/auth.middleware");
const express = require("express");

const AuthRouter = express.Router();

// Login Route
AuthRouter.post("/login", async (request, response) => {
  const { email, password } = request.body;

  if (!email || !password) {
    return response.status(400).json({
      message: "Email or password is missing!",
    });
  }

  try {
    // Find user by email
    const user = await UserModel.findOne({ email });
    if (!user) {
      return response.status(404).json({
        message: "User not found!",
      });
    }

    // Compare hashed password with provided password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return response.status(401).json({
        message: "Invalid credentials!",
      });
    }

    // Generate token
    const token = generateToken(
      {
        username: user.username,
        email: user.email,
      },
      user._id
    );

    return response.status(200).json({
      message: "Sign in successfully!",
      token: `Bearer ${token}`,
    });
  } catch (error) {
    return response.status(500).json({
      message: "Something went wrong!",
      error: error.message,
    });
  }
});

// Signup Route
AuthRouter.post("/signup", async (request, response) => {
  const { username, email, password } = request.body;

  if (!username || !email || !password) {
    return response.status(400).json({
      message: "Required fields are missing!",
    });
  }

  try {
    // Check if user already exists
    const existingUser = await UserModel.findOne({ email });
    if (existingUser) {
      return response.status(409).json({
        message: "Email is already registered!",
      });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create and save the user
    const newUser = new UserModel({
      username,
      email,
      password: hashedPassword,
    });

    const result = await newUser.save();

    return response.status(201).json({
      message: "Sign up successfully!",
    });
  } catch (error) {
    return response.status(500).json({
      message: "Something went wrong!",
      error: error.message,
    });
  }
});

// Route to get all users (protected route)
AuthRouter.get("/", creationGuard, async (request, response) => {
  try {
    const users = await UserModel.find();

    if (users.length === 0) {
      return response.status(404).json({
        message: "No users found",
      });
    }

    return response.status(200).json({
      message: "Users fetched successfully",
      users: users,
    });
  } catch (error) {
    return response.status(500).json({
      error: error.message,
      message: "Something went wrong while fetching users",
    });
  }
});

// Route to get a user by ID (protected route)
AuthRouter.get("/:id", creationGuard, async (request, response) => {
  const { id } = request.params;

  try {
    const user = await UserModel.findById(id);

    if (!user) {
      return response.status(404).json({
        message: "User not found",
      });
    }

    return response.status(200).json({
      message: "User fetched successfully",
      user: user,
    });
  } catch (error) {
    return response.status(500).json({
      error: error.message,
      message: "Something went wrong while fetching the user",
    });
  }
});

module.exports = AuthRouter;
