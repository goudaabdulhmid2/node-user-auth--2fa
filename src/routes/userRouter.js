const express = require("express");

const {
  getAllUsers,
  createUser,
  getUser,
} = require("./../controllers/userController");
const { protect, restrictTo } = require("./../controllers/authController");

const {
  createUserValidator,
  getUserValidator,
} = require("../utlis/validator/userValidation");

const router = express.Router();

router.use(protect, restrictTo("admin"));
router.route("/").get(getAllUsers).post(createUserValidator, createUser);
router.route("/:id").get(getUserValidator, getUser);

module.exports = router;
