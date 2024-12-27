const jwt = require("jsonwebtoken");
const { Secret_Key } = require("../jwt.util");

function creationGuard(request, response, next) {
  // Check if the 'Authorization' header contains the token
  const token = request.headers["authorization"]?.split(" ")[1]; // Extract token from 'Bearer <token>'

  if (!token) {
    return response.status(403).json({
      message: "Token is missing or invalid format!",
    });
  }

  try {
    // Verify the token using the Secret_Key
    const decoded = jwt.verify(token, Secret_Key);

    // Token is valid, proceed to the next middleware or route handler
    request.user = decoded; // Attach decoded token to the request object if you need user info later
    next();
  } catch (err) {
    // Handle different types of errors
    if (err.name === "TokenExpiredError") {
      return response.status(401).json({
        message: "Token has expired!",
        error: err.message,
      });
    }
    return response.status(401).json({
      message: "Unauthorized! Invalid token!",
      error: err.message,
    });
  }
}

module.exports = { creationGuard };
