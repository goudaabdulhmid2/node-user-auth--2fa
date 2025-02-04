const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const catchAsync = require("express-async-handler");

const genrateToken = (id, verified2FA = false) => {
  return jwt.sign({ id, verified2FA }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};

const generateTempToken = (id) =>
  jwt.sign(
    {
      id,
      purpose: "2fa-verification",
    },
    process.env.JWT_SECRET,
    { expiresIn: "5m" }
  );

const generateRefreshToken = () => crypto.randomBytes(32).toString("hex");

const hashRefreshToken = (token) => {
  return crypto.createHash("sha256").update(token).digest("hex");
};

const createToken = (user, req, res, verified2FA = false) => {
  const token = genrateToken(user.id, verified2FA);
  // jwt
  const cookieOptionsForToken = {
    expires: new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 60 * 1000
    ),
    secure: process.env.NODE_ENV === "production",
    httpOnly: true,
    sameSite: "strict",
  };
  res.cookie("jwt", token, cookieOptionsForToken);
  return token;
};

const refreshToken = catchAsync(async (user, req, res) => {
  const newRefreshToken = generateRefreshToken();
  // refersh jwt
  const cookieOptionsForRefersh = {
    expires: new Date(
      Date.now() + process.env.JWT_REFRESH_EXPIRES_IN * 24 * 60 * 60 * 1000
    ),
    secure: process.env.NODE_ENV === "production",
    httpOnly: true,
    sameSite: "strict",
  };
  res.cookie("refreshToken", newRefreshToken, cookieOptionsForRefersh);

  user.refreshToken = hashRefreshToken(newRefreshToken);
  await user.save({ validateBeforeSave: false });
});

module.exports = {
  hashRefreshToken,
  createToken,
  refreshToken,
  genrateToken,
  generateRefreshToken,
  generateTempToken,
};
