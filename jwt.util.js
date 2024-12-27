const jwt = require("jsonwebtoken");

// Use environment variable for sensitive data like the secret key.
const Secret_Key = process.env.JWT_SECRET || "default_secret";

function generateToken(data = {}, userId = "") {
  // Validate inputs to avoid unexpected errors
  if (!userId) {
    throw new Error("User ID is required to generate a token.");
  }

  const token = jwt.sign(
    {
      ...data,
    },
    Secret_Key,
    {
      expiresIn: "1h", // Token validity duration
      subject: String(userId), // Sets the `sub` claim
      issuer: "authenticator", // Sets the `iss` claim
    }
  );

  return token;
}

module.exports = { generateToken, Secret_Key };
