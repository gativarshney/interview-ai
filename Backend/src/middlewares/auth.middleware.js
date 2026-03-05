const jwt = require("jsonwebtoken");
const tokenBlackListModel = require("../models/blacklist.model.js");

async function authUser(req, res, next) {
  const token = req.cookies.token;
  if (!token) {
    return res.status(401).json({
      message: "Token not provided",
    });
  }
  const isBlackListed = await tokenBlackListModel.findOne({ token });
  if (isBlackListed) {
    return res.status(401).json({
      message: "Token is invalid",
    });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({
      message: "Invalid Token",
    });
  }
}

module.exports = { authUser };
