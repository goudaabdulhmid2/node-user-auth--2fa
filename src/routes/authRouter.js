const express = require("express");
const passport = require("passport");

const {
  signup,
  refreshAccessToken,
  login,
  protect,
  restrictTo,
  logout,
  socialLoginHandler,
  setup2FA,
  authStatus,
  verify2FA,
  reset2FA,
  generateBackupCode,
  verifyBackupCode,
  requestRecoveryOTP,
  verifyRecoveryOTP,
  requestRecoverySMS,
  verifyRecoverySMS,
} = require("../controllers/authController");
const {
  signupValidator,
  loginValidator,
} = require("../utlis/validator/authValidation");

const router = express.Router();

// ======================
// Public Routes
// ======================

// Social Auth
router.get(
  "/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);
router.get(
  "/google/callback",
  passport.authenticate("google", {
    failureRedirect: "/login",
    session: false, // Disable sessions (we're using JWT)
  }),
  socialLoginHandler
);

router.get(
  "/facebook",
  passport.authenticate("facebook", { scope: ["email"] })
);
router.get(
  "/facebook/callback",
  passport.authenticate("facebook", {
    failureRedirect: "/login",
    session: false,
  }),
  socialLoginHandler
);

// Core Auth
router.post("/signup", signupValidator, signup);
router.post("/login", loginValidator, login);
router.post("/refresh-token", refreshAccessToken);

// ======================
// Protected Routes
// ======================
router.use(protect);

// 2FA Management
router.post("/2fa", setup2FA);
router.post("/2fa/verify", verify2FA);
router.delete("/2fa", reset2FA);

// Logout
router.post("/logout", logout);

// Backup Codes
router.post("/backup-codes", generateBackupCode);
router.post("/backup-codes/verify", verifyBackupCode);

// OTP Recovery via email
router.post("/2fa/recovery-code", requestRecoveryOTP);
router.post("/2fa/recovery-code/verify", verifyRecoveryOTP);

// OTP Recovery via SMS
router.post("/2fa/recovery/request-sms", requestRecoverySMS);
router.post("/2fa/recovery/verify-sms", verifyRecoverySMS);

module.exports = router;
