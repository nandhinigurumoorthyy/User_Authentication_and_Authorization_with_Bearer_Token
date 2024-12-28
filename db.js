const mongoose = require("mongoose");

// Use environment variable or fallback URI for local development
const mongoDBURI = process.env.MONGO_URI || "mongodb://localhost:27017/user";

async function createDbConnection() {
  try {
    await mongoose.connect(mongoDBURI); // Removed deprecated options
    console.log("Database connection established successfully!");
  } catch (error) {
    console.error("Error connecting to the database:", error.message);
    process.exit(1); // Exit the application if the database connection fails
  }
}

module.exports = {
  createDbConnection,
};
