const { check } = require("express-validator");

const handleValidationErrors = require("../../controllers/validatorController");
const catchAsync = require("express-async-handler");
const User = require("../../models/user");

exports.createUserValidator = [
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
  check("profileImage")
    .optional()
    .isString()
    .withMessage("Profile image must be a string"),
  check("brithdate")
    .notEmpty()
    .withMessage("Brithdate is required.")
    .isDate()
    .withMessage("Please enter a valid date.")
    .custom((val) => {
      const today = new Date();
      const birthDate = new Date(val);
      const age = today.getFullYear() - birthDate.getFullYear();
      if (age < 18) {
        throw new Error("You must be at least 18 years old.");
      }
      req.age = age;
      return true;
    }),
  check("phone")
    .optional()
    .isMobilePhone()
    .withMessage("Please enter a valid phone number."),
  check("gender")
    .notEmpty()
    .withMessage("Gender is required.")
    .trim()
    .toLowerCase()
    .isIn(["male", "female", "other", "prefer not to say"])
    .withMessage(
      "Gender must be one of: male, female, other, or prefer not to say."
    ),
  handleValidationErrors,
];

exports.getUserValidator = [
  check("id").isMongoId().withMessage("Invalid user ID"),
  handleValidationErrors,
];
