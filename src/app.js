const express = require("express");
const morgan = require("morgan");
const cookieParser = require("cookie-parser");

const passport = require("./config/passport");
const ApiError = require("./utlis/ApiError");
const userRouter = require("./routes/userRouter");
const authRouter = require("./routes/authRouter");
const globalErrorHandler = require("./controllers/errorController");

const app = express();

app.use(express.json({ limit: "100mb" }));
app.use(
  express.urlencoded({
    extended: true,
    limit: "100mb",
  })
);
app.use(cookieParser());

if (process.env.NODE_ENV === "development") {
  app.use(morgan("dev"));
}

// passport
app.use(passport.initialize());

app.use("/api/v1/users", userRouter);
app.use("/api/v1/auth", authRouter);

// Unhandled Routes
app.all("*", (req, res, next) => {
  next(new ApiError(`Can't find ${req.originalUrl} on this server!.`, 404));
});

app.use(globalErrorHandler);
module.exports = app;
