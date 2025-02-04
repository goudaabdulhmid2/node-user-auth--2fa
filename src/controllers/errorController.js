const ApiError = require("./../utlis/ApiError");
const handleCastErrorDB = (err) => {
  const message = `Invalid ${err.path}:${err.value}`;
  return new ApiError(message, 400);
};
const handleDuplicateFieldsDB = (err) => {
  const value = err.errmsg.match(/(["'])(?:\\.|.)*?\1/)?.[0] || "unknown";
  const message = `Duplicate field value: ${value}. Please use another value`;
  return new ApiError(message, 400);
};

const handleValidationErrorDB = (err) => {
  const errors = Object.values(err.errors)
    .map((el) => el.message)
    .join(". ");
  const message = `Invalid input data. ${errors}`;
  return new ApiError(message, 400);
};

const handleJwtError = () => {
  const message = "Invalid token. Please login again...";
  return new ApiError(message, 401);
};

const handleExpiredError = () => {
  const message = "Token expired. Please login again...";
  return new ApiError(message, 401);
};

const handleCsrfError = () => {
  const message = "Invalid CSRF token";
  return new ApiError(message, 403);
};

const sendErrorProd = (err, res) => {
  if (err.isOperational || err instanceof ApiError) {
    return res.status(err.statusCode).json({
      status: err.status,
      message: err.message,
    });
  }
  return res.status(500).json({
    status: "error",
    message: "Something went very wrong!",
  });
};

const sendErrorDev = (err, res) => {
  res.status(err.statusCode).json({
    status: err.status,
    error: err,
    message: err.message,
    stack: err.stack,
  });
};

module.exports = (err, req, res, next) => {
  err.statusCode = err.statusCode || 500;
  err.status = err.status || "error";
  if (process.env.NODE_ENV === "development") {
    sendErrorDev(err, res);
  } else if (process.env.NODE_ENV === "production") {
    let error = Object.assign({}, err);
    error.message = err.message;

    console.log(error);

    if (error.name === "CastError") error = handleCastErrorDB(error);
    if (error.code === 11000) error = handleDuplicateFieldsDB(error);
    if (error.name === "ValidationError")
      error = handleValidationErrorDB(error);
    if (error.name === "JsonWebTokenError") error = handleJwtError();
    if (error.name === "TokenExpiredError") error = handleExpiredError();
    if (error.code === "EBADCSRFTOKEN") error = handleCsrfError();

    sendErrorProd(error, res);
  }
};
