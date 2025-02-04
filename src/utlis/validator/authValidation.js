const { check } = require("express-validator");
const slugify = require("slugify");
const catchAsync = require("express-async-handler");

const catchError = require("../../controllers/validatorController");
const User = require("../../models/user");

exports.signupValidator = [
  check("name")
    .notEmpty()
    .withMessage("Name is required")
    .isLength({ min: 3 })
    .withMessage("Too short user name"),
  check("email")
    .notEmpty()
    .withMessage("Email is required")
    .isEmail()
    .withMessage("Please enter a valid email")
    .custom(
      catchAsync(async (val) => {
        const user = await User.findOne({ email: val });

        if (user) {
          throw new Error("Email already exists");
        }

        return true;
      })
    ),
  check("password")
    .notEmpty()
    .withMessage("Password is required")
    .isLength({ min: 8 })
    .withMessage("Please enter a valid password")
    .custom((val, { req }) => {
      if (val !== req.body.passwordConfirm) {
        throw new Error("Passwords do not match");
      }
      return true;
    }),
  check("passwordConfirm")
    .notEmpty()
    .withMessage("PasswordConfirm is required"),
  check("profileImage").optional(),
  check("phone")
    .optional()
    .isMobilePhone(["ar-EG", "ar-SA"])
    .withMessage(
      "Please enter a valid phone number! only accept EG or SA phone numbers"
    ),
  catchError,
];
exports.loginValidator = [
  check("email")
    .notEmpty()
    .withMessage("Email is required")
    .isEmail()
    .withMessage("Invalid email address"),
  check("password").notEmpty().withMessage("Password is required"),
  catchError,
];
