const multer = require("multer");
const AppError = require("../utlis/ApiError");

const multerSettings = () => {
  // Multer Storge
  const multerStorge = multer.memoryStorage();

  // Multer Filter
  const multerFilter = (req, file, cb) => {
    if (file.mimetype.startWith("image")) {
      cb(null, true);
    } else {
      cb(new AppError("Only image fiels are allowed", 400), false);
    }
  };

  return multer({
    storage: multerStorge,
    fileFilter: multerFilter,
  });
};

exports.uploadSingleImage = (fieldName) => multerSettings().single(fieldName);

exports.uploadMultipleImages = (arrayOfFields) =>
  multerSettings().fields(arrayOfFields);
