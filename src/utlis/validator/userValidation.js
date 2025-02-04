const { check } = require("express-validator");

const catchError = require("../../controllers/validatorController");
const catchAsync = require("express-async-handler");
const User = require("../../models/user");

exports.createUserValidator = [
  check("name").notEmpty().withMessage("Name is required."),
  check("email")
    .notEmpty()
    .withMessage("Email is required.")
    .isEmail()
    .withMessage("Please enter valid email.")
    .custom(
      catchAsync(async (val) => {
        const user = await User.findOne({ email: val });

        if (user) {
          throw new Error("Email is already exist.");
        }

        return true;
      })
    ),
  check("password")
    .notEmpty()
    .withMessage('"Password is required"')
    .isLength({ min: 8 })
    .withMessage("Password is short.")
    .custom((val, { req }) => {
      if (val !== req.body.passwordConfirm) {
        throw new Error("Password do not match.");
      }
      return true;
    }),
  check("passwordConfirm").notEmpty().withMessage("Password Confirm required."),
  check("profileImage").optional(),
  check("role").optional(),
  check("phone")
    .optional()
    .isMobilePhone(["ar-EG", "ar-SA"])
    .withMessage("Please enter a valid Phone number."),
  catchError,
];

exports.getUserValidator = [
  check("id").isMongoId().withMessage("Invalid user ID"),
  catchError,
];
