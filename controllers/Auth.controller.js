const bcrypt = require("bcrypt");
const UserModel = require("../model/User.model");
const { generateToken } = require("../jwt.util");
const { creationGuard } = require("../middleware/auth.middleware");
const express = require("express");

const AuthRouter = express.Router();

// create a user
AuthRouter.post("/create", async (request, response) => {
  const { password, ...rest } = request.body;

  // Validate input fields
  if (!password || !rest.email || !rest.username) {
    return response.status(400).json({
      message: "Required fields are missing!",
    });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(rest.email)) {
    return response.status(400).json({
      message: "Invalid email format!",
    });
  }

  if (password.length < 8) {
    return response.status(400).json({
      message: "Password must be at least 8 characters long!",
    });
  }

  try {
    // Check if email already exists
    const existingUser = await UserModel.findOne({ email: rest.email });
    if (existingUser) {
      return response.status(409).json({
        message: "Email is already registered!",
      });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create and save the user
    const user = new UserModel({
      ...rest,
      password: hashedPassword,
    });

    const result = await user.save();

    return response.status(201).json({
      message: "User created successfully!",
      user: {
        id: result._id,
        username: result.username,
        email: result.email,
      },
    });
  } catch (error) {
    console.error("Error creating user:", error);
    return response.status(500).json({
      error: error.message,
      message: "Something went wrong!",
    });
  }
});


// Route to login a user
AuthRouter.post("/login", async (request, response) => {
  const { email, password } = request.body;
  console.log("email: ", email, "password: ", password);

  if (!email || !password) {
    return response.status(400).json({
      message: "Email or password is missing!",
    });
  }

  try {
    const user = await UserModel.findOne({ email });
    console.log("user", user);
    if (!user) {
      return response.status(404).json({
        message: "User not found",
      });
    }

    // Compare entered password with hashed password in the database
    const isMatch = await bcrypt.compare(String(password), user.password);
    console.log("Password match:", isMatch);

    if (!isMatch) {
      return response.status(401).json({
        message: "Invalid credentials",
      });
    }

    // Generate the token upon successful login
    const token = generateToken(
      {
        email: user.email,
        username: user.username,
      },
      user._id
    );

    return response.status(200).json({
      message: "Logged in successfully",
      token: `Bearer ${token}`, // Return the Bearer token
    });
  } catch (error) {
    console.error("Error during login:", error);
    return response.status(500).json({
      error: error.message,
      message: "Something went wrong!",
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
