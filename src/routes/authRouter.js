const express = require("express");
const passport = require("passport");
const rateLimit = require("express-rate-limit");

const {
  signup,
  refreshAccessToken,
  login,
  protect,
  restrictTo,
  logout,
  socialLoginHandler,
  setup2FA,
  verify2FA,
  reset2FA,
  generateBackupCode,
  verifyBackupCode,
  requestRecoveryOTP,
  verifyRecoveryOTP,
  requestRecoverySMS,
  verifyRecoverySMS,
  forgetPassword,
  verifyResetCode,
  resetPassword,
  verifyEmail,
  resendVerificationEmail,
  logoutAll,
  reAuth
} = require("../controllers/authController");
const {
  signupValidator,
  loginValidator,
  verify2FAValidator,
  verifyBackupCodeValidator,
  verifyRecoveryValidator,
  forgetPasswordValidator,
  resetPasswordValidator,
  verifyEmailValidator,
} = require("../utlis/validator/authValidation");

const router = express.Router();

// Stricter limiter for sensitive routes
const strictLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 5, // 5 attempts
  keyGenerator: (req, res) => (req.user ? req.user.id : req.ip),
  message: "Too many attempts. Please try again in 1 minute.",
});

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
router.post("/signup", strictLimiter, signupValidator, signup);
router.post("/login", strictLimiter, loginValidator, login);
router.post("/refresh-token", refreshAccessToken);

// Reset password
router.post(
  "/forgot-password",
  strictLimiter,
  forgetPasswordValidator,
  forgetPassword
);
router.post(
  "/verify-reset-code",
  strictLimiter,
  verifyRecoveryValidator,
  verifyResetCode
);
router.post(
  "/reset-password",
  strictLimiter,
  resetPasswordValidator,
  resetPassword
);

// verify email
router.post("/verify-email", strictLimiter, verifyEmailValidator, verifyEmail);
router.post("/resend-verification-email", resendVerificationEmail);

// ======================
// Protected Routes
// ======================
router.use(protect);

// 2FA Management
router.post("/2fa", setup2FA);
router.post("/2fa/verify", strictLimiter, verify2FAValidator, verify2FA);
router.delete("/2fa", reset2FA);

// Logout
router.post("/logout", logout);

// Logout from all devices
router.post("/logout-all", reAuth, logoutAll);

// Backup Codes
router.post("/backup-codes", generateBackupCode);
router.post(
  "/backup-codes/verify",
  strictLimiter,
  verifyBackupCodeValidator,
  verifyBackupCode
);

// OTP Recovery via email
router.post("/2fa/recovery-code", requestRecoveryOTP);
router.post(
  "/2fa/recovery-code/verify",
  strictLimiter,
  verifyRecoveryValidator,
  verifyRecoveryOTP
);

// OTP Recovery via SMS
router.post("/2fa/recovery/request-sms", requestRecoverySMS);
router.post(
  "/2fa/recovery/verify-sms",
  strictLimiter,
  verifyRecoveryValidator,
  verifyRecoverySMS
);

module.exports = router;
