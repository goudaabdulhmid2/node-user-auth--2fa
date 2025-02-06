const express = require("express");
const rateLimit = require("express-rate-limit");
const mongoSanitize = require("express-mongo-sanitize");
const xss = require("xss-clean");
const compression = require("compression");
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

// Parse cookies
app.use(cookieParser());

// Compress all response
app.use(compression());

// passport
app.use(passport.initialize());

if (process.env.NODE_ENV === "development") {
  app.use(morgan("dev"));
}

// General rate limiter for API routes
const limiter = rateLimit({
  window: 15 * 60 * 1000,
  max: 100,
  message: "Too many requests from this IP, please try again in an 15 minutes!",
});
app.use("/api", limiter);

// Authentication-based rate limiter (login attempts)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  keyGenerator: (req, res) => (req.user ? req.user.id : req.ip),
  message: "Too many login attempts. Please try again later.",
});
app.use("/api/v1/auth/login", authLimiter);

// Apply data senitization
app.use(mongoSanitize());
app.use(xss());

app.use("/api/v1/users", userRouter);
app.use("/api/v1/auth", authRouter);

// Unhandled Routes
app.all("*", (req, res, next) => {
  next(new ApiError(`Can't find ${req.originalUrl} on this server!.`, 404));
});

app.use(globalErrorHandler);
module.exports = app;
