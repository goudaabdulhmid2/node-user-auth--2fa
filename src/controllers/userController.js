const catchAsync = require("express-async-handler");
const uuid = require("uuid");
const sharp = require("sharp");

const { getAll, getOne, createOne } = require("./handlerFactory");
const { uploadSingleImage } = require("./uploadImageController");
const User = require("./../models/user");

exports.getAllUsers = getAll(User);

exports.getUser = getOne(User);

exports.createUser = createOne(User);

// @desc Upload profile image for user
exports.uploadProfileImage = uploadSingleImage("profileImage");

// @desc Resize and upload profile image
exports.resizeProfileImage = catchAsync(async (req, res, next) => {
  if (!req.file) return next();

  req.file.filename = `user-${uuid.v4()}-${Date.now()}.jpeg`;

  await sharp(req.file.buffer)
    .resize(600, 600)
    .toFormat("jpeg")
    .jpeg({ quality: 90 })
    .toFile(`uploads/users/${req.file.filename}`);

  req.body.profileImage = req.file.filename;
  next();
});
