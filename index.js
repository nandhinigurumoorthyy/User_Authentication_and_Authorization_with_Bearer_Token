require("dotenv").config();

const AuthRouter = require("./controllers/Auth.controller");
const { createDbConnection } = require("./db");

// Establish database connection
createDbConnection();

const express = require("express");
const API_server = express();

// Serve static files
API_server.use(express.static("public"));

// Parse incoming body as JSON
API_server.use(express.json());

// Inject Routers
API_server.use("/usr", AuthRouter);

// Start the server
const PORT = process.env.PORT || 3000; // Render automatically provides a PORT environment variable
const HOSTNAME = "0.0.0.0"; // Required for Render to bind to all interfaces

API_server.listen(PORT, HOSTNAME, function () {
  console.log(`Server Started at http://${HOSTNAME}:${PORT}`);
});
