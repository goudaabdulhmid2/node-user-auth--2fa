const { check } = require("express-validator");

const handleValidationErrors = require("../../controllers/validatorController");
const User = require("../../models/user");

// Core auth
exports.signupValidator = [
  check("firstName")
    .notEmpty()
    .withMessage("First name is required.")
    .isLength({ min: 3 })
    .withMessage("First name must be at least 3 characters long."),
  check("secondName")
    .notEmpty()
    .withMessage("Second name is required.")
    .isLength({ min: 3 })
    .withMessage("Second name must be at least 3 characters long."),

  check("email")
    .notEmpty()
    .withMessage("Email is required.")
    .isEmail()
    .withMessage("Please enter a valid email.")
    .custom(async (val) => {
      const user = await User.findOne({ email: val });

      if (user) {
        throw new Error("Email already exists.");
      }

      return true;
    }),

  check("password")
    .notEmpty()
    .withMessage("Password is required.")
    .isLength({ min: 8 })
    .withMessage("Password must be at least 8 characters long.")
    .matches(/[a-z]/)
    .withMessage("Password must contain at least one lowercase letter.")
    .matches(/[A-Z]/)
    .withMessage("Password must contain at least one uppercase letter.")
    .matches(/\d/)
    .withMessage("Password must contain at least one digit.")
    .matches(/[@$!%*?&]/)
    .withMessage(
      "Password must contain at least one special character (@$!%*?&)."
    ),

  check("passwordConfirm")
    .notEmpty()
    .withMessage("Password confirmation is required.")
    .custom((val, { req }) => {
      if (val !== req.body.password) {
        throw new Error("Passwords do not match.");
      }
      return true;
    }),
  check("profileImage").optional(),
  check("phone")
    .optional()
    .isMobilePhone()
    .withMessage("Please enter a valid phone number."),
  handleValidationErrors,
];
exports.loginValidator = [
  check("email")
    .notEmpty()
    .withMessage("Email is required.")
    .isEmail()
    .withMessage("Invalid email address.")
    .normalizeEmail(),

  check("password")
    .notEmpty()
    .withMessage("Password is required.")
    .isLength({ min: 8 })
    .withMessage("Password must be at least 8 characters long."),

  handleValidationErrors,
];

// 2FA
exports.verify2FAValidator = [
  check("token")
    .notEmpty()
    .withMessage("2FA token is required.")
    .isNumeric()
    .isLength({ min: 6, max: 6 })
    .withMessage("2FA token must be a 6-digit number."),
  handleValidationErrors,
];

// BackupCode
exports.verifyBackupCodeValidator = [
  check("backupCode")
    .notEmpty()
    .withMessage("Backup code is required.")
    .isString()
    .isLength({ min: 8, max: 8 })
    .withMessage("Backup code must be between 8-16 characters."),

  handleValidationErrors,
];

// Recovery OTP
exports.verifyRecoveryValidator = [
  check("otp")
    .notEmpty()
    .withMessage("OTP is required.")
    .isNumeric()
    .isLength({ min: 6, max: 6 })
    .withMessage("OTP must be a 6-digit number."),

  handleValidationErrors,
];

// Reset Password
exports.forgetPasswordValidator = [
  check("email")
    .notEmpty()
    .withMessage("Email is required.")
    .isEmail()
    .withMessage("Invalid email address.")
    .normalizeEmail(),
  handleValidationErrors,
];
exports.resetPasswordValidator = [
  check("email")
    .notEmpty()
    .withMessage("Email is required.")
    .isEmail()
    .withMessage("Invalid email address.")
    .normalizeEmail(),

  check("newPassword")
    .notEmpty()
    .withMessage("New password is required.")
    .isLength({ min: 8 })
    .withMessage("Password must be at least 8 characters long.")
    .matches(/[a-z]/)
    .withMessage("Password must contain at least one lowercase letter.")
    .matches(/[A-Z]/)
    .withMessage("Password must contain at least one uppercase letter.")
    .matches(/\d/)
    .withMessage("Password must contain at least one digit.")
    .matches(/[@$!%*?&]/)
    .withMessage(
      "Password must contain at least one special character (@$!%*?&)."
    ),
  check("confirmNewPassword")
    .notEmpty()
    .withMessage("New password confirmation is required.")
    .custom((val, { req }) => {
      if (val !== req.body.newPassword) {
        throw new Error("Passwords do not match.");
      }
      return true;
    }),
  handleValidationErrors,
];
