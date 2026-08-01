const jwt = require("jsonwebtoken");
const tokenBlackListModel = require("../models/blacklist.model.js");

async function authUser(req, res, next) {
  const token = req.cookies.token;
  if (!token) {
    return res.status(401).json({
      message: "Token not provided",
    });
  }

  try {
    // Verify the signature first: an invalid token is not worth a DB round trip.
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const isBlackListed = await tokenBlackListModel.exists({ token });
    if (isBlackListed) {
      return res.status(401).json({
        message: "Token is invalid",
      });
    }

    req.user = decoded;
    next();
  } catch (error) {
    if (error.name === "TokenExpiredError" || error.name === "JsonWebTokenError") {
      return res.status(401).json({
        message: "Invalid Token",
      });
    }
    return next(error);
  }
}

module.exports = { authUser };
