const catchAsync = require("express-async-handler");
const jwt = require("jsonwebtoken");
const speakeasy = require("speakeasy");
const QRCode = require("qrcode");
const crypto = require("crypto");

const User = require("../models/user");
const {
  createToken,
  refreshToken,
  hashRefreshToken,
  generateTempToken,
} = require("../utlis/createToken");
const sanitizeUser = require("../utlis/sanitizeUser");
const ApiError = require("../utlis/ApiError");
const Email = require("../utlis/Email");
const SMS = require("../utlis/SMS");

// Core Auth
exports.signup = catchAsync(async (req, res, next) => {
  const newUser = await User.create({
    name: req.body.name,
    email: req.body.email,
    password: req.body.password,
    phone: req.body.phone,
    profileImage: req.body.profileImage,
  });

  const token = createToken(newUser, req, res);
  await refreshToken(newUser, req, res);
  await new Email(newUser, "").sendWelcome();

  res.status(201).json({
    status: "success",
    token,
    data: {
      user: sanitizeUser(newUser),
    },
  });
});

exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;

  // 1. Check if email/password exist
  if (!email?.trim() || !password?.trim()) {
    return next(new ApiError("Please provide email and password", 400));
  }

  // 2. Find user and validate credentials
  const user = await User.findOne({ email }).select("+password");
  if (!user || !(await user.correctPassword(password, user.password))) {
    return next(new ApiError("incorrect email or password.", 401));
  }

  // 3. Handle 2FA
  if (user.twoFactorEnabled) {
    const tempToken = generateTempToken(user.id);
    return res.status(200).json({
      status: "2fa-required",
      token: tempToken,
      message: "Two-factor authentication required",
    });
  }

  // 4. Regular login without 2FA
  const token = createToken(user, req, res);
  await refreshToken(user, req, res);

  // send response
  res.status(200).json({
    status: "success",
    token,
    data: {
      user: sanitizeUser(user),
    },
  });
});

exports.logout = catchAsync(async (req, res, next) => {
  // 1. Check user
  if (!req.user) {
    return next(new ApiError("Unauthorized user", 401));
  }
  // 2. Clear cookies
  res.clearCookie("jwt");
  res.clearCookie("refreshToken");

  // 3. Ivalidate refresh token
  const user = await User.findById(req.user.id);
  user.refreshToken = undefined;
  await user.save({ validateBeforeSave: false });

  res.status(200).json({
    status: "success",
    message: "Logged out successfully",
  });
});

exports.protect = catchAsync(async (req, res, next) => {
  // 1. Get token from headers/cookies
  const token = req.headers.authorization?.startsWith("Bearer")
    ? req.headers.authorization.split(" ")[1]
    : req.cookies.jwt;

  if (!token || token === "null") {
    return next(new ApiError("Unauthorized access", 401));
  }

  // 2. Verify token
  const decoded = await jwt.verify(token, process.env.JWT_SECRET);

  // 3. Check user existence
  const currentUser = await User.findById(decoded.id);
  if (!currentUser) {
    return next(new ApiError("User no longer exists.", 401));
  }

  // 4. Check password change
  if (currentUser.changedPasswordAfter(decoded.iat)) {
    return next(
      new ApiError("User has changed password. Please log in again.", 401)
    );
  }

  // 5. Restrict tempToken to specific route
  const enablePaths = [
    "/2fa/verify",
    "/backup-codes/verify",
    "/2fa/recovery-code",
    "/2fa/recovery-code/verify",
    "/2fa/recovery/request-sms",
    "/2fa/recovery/verify-sms",
  ];
  if (
    decoded.purpose === "2fa-verification" &&
    !enablePaths.includes(req.path)
  ) {
    return next(new ApiError("Access denied. Complete 2FA first.", 403));
  }

  // 6. Enforce 2FA verification for regular tokens
  if (
    currentUser.twoFactorEnabled &&
    !decoded.verified2FA &&
    !decoded.purpose
  ) {
    return next(new ApiError("Two-factor authentication required", 401));
  }

  req.user = currentUser;
  next();
});
exports.restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return next(
        new ApiError("You do not have permission to access this route.", 403)
      );
    }
    next();
  };
};

exports.refreshAccessToken = catchAsync(async (req, res, next) => {
  const token = req.headers.authorization?.startsWith("Bearer")
    ? req.headers.authorization.split(" ")[1]
    : req.cookies.jwt;

  const refreshTokenCookie = req.cookies.refreshToken;
  if (!refreshTokenCookie) {
    return next(new ApiError("No refresh token provided", 401));
  }

  // check user
  const hashedToken = hashRefreshToken(refreshTokenCookie);
  const user = await User.findOne({ refreshToken: hashedToken });
  if (!user) {
    return next(new ApiError("Invalid refresh token.", 401));
  }

  const decoded = await jwt.verify(token, process.env.JWT_SECRET);

  // create newOne
  const newAccessToken = createToken(
    user,
    req,
    res,
    user.twoFactorEnabled ? decoded.verified2FA : false
  );
  await refreshToken(user, req, res);

  res.status(200).json({
    status: "success",
    token: newAccessToken,
  });
});

// Social Auth
exports.socialLoginHandler = catchAsync(async (req, res, next) => {
  const user = req.user;

  if (!user) {
    return next(new ApiError("Authentication failed", 401));
  }

  // If 2FA is enabled, require verification before issuing a token
  if (user.twoFactorEnabled) {
    const tempToken = generateTempToken(user.id);
    return res.status(200).json({
      status: "2fa-required",
      token: tempToken,
      message: "Two-factor authentication required",
    });
  }

  // No 2FA? Issue token immediately
  const token = createToken(user, req, res);
  await refreshToken(user, req, res);

  res.status(200).json({
    status: "success",
    token,
    message: `${user.provider} login successful`,
    data: {
      user: sanitizeUser(user),
    },
  });
});

// 2FA
exports.setup2FA = catchAsync(async (req, res, next) => {
  const user = req.user;

  // 1. Generate TOTP Secret
  const secret = speakeasy.generateSecret({
    name: `${process.env.APP_NAME} (${user.email})`,
    issuer: "Gouda Company",
  });

  // 2. Store secret temporarily (not enabling 2FA yet)
  user.twoFactorTempSecret = secret.base32;
  await user.save({ validateBeforeSave: false });

  // 3. Genrate QR Code
  QRCode.toDataURL(secret.otpauth_url, (err, qrCode) => {
    if (err) return next(new ApiError("Failed to generate QR code", 500));

    res.status(200).json({
      status: "success",
      data: {
        qrCode,
        manualCode: secret.base32, // For manual entry
      },
    });
  });
});

exports.verify2FA = catchAsync(async (req, res, next) => {
  const { token } = req.body;
  const user = req.user;

  if (!user.twoFactorEnabled && !user.twoFactorTempSecret) {
    return next(new ApiError("2FA setup not initiated", 400));
  }

  // 1. Verify OTP
  const verified = speakeasy.totp.verify({
    secret: user.twoFactorEnabled
      ? user.twoFactorSecret
      : user.twoFactorTempSecret,
    encoding: "base32",
    token,
    window: 1,
  });

  if (!verified) return next(new ApiError("Invalid authentication code", 401));

  // 2. Enable 2FA and save secret permanently
  user.twoFactorSecret = user.twoFactorSecret || user.twoFactorTempSecret;
  user.twoFactorEnabled = true;
  user.twoFactorTempSecret = undefined; // Remove temporary secret
  await user.save({ validateBeforeSave: false });

  // 3. Generate new JWT token with 2FA verified
  const newToken = createToken(user, req, res, true);
  await refreshToken(user, req, res);

  res.status(200).json({
    status: "success",
    token: newToken,
    data: {
      user: sanitizeUser(user),
    },
  });
});

exports.reset2FA = catchAsync(async (req, res, next) => {
  const user = req.user;

  user.twoFactorEnabled = false;
  user.twoFactorSecret = undefined;
  await user.save({ validateBeforeSave: false });

  res.status(200).json({
    status: "success",
    message: "Two-factor authentication disabled",
  });
});

// Backup codes
exports.generateBackupCode = catchAsync(async (req, res, next) => {
  const user = req.user;

  if (!user?.twoFactorEnabled) {
    return next(new ApiError("2FA is not enabled for this account", 400));
  }

  // Genrate 10 unique backup code
  const codes = Array.from({ length: 10 }, () =>
    crypto.randomBytes(4).toString("hex")
  );

  // Hash codes before storing
  user.backupCodes = codes.map((code) => user.hashBackupCode(code));
  await user.save({ validateBeforeSave: false });

  res.status(200).json({
    status: "success",
    message: "Backup codes generated. Store them safely!",
    data: { backupCodes: codes }, // Send plain text for user to save
  });
});
exports.verifyBackupCode = catchAsync(async (req, res, next) => {
  const { backupCode } = req.body;
  const user = req.user;

  if (!user?.twoFactorEnabled) {
    return next(new ApiError("2FA is not enabled for this account", 400));
  }

  if (!user.verifyBackupCode(backupCode)) {
    return next(new ApiError("Invalid or expired backup code", 401));
  }

  await user.save({ validateBeforeSave: false });

  // Generate new token with 2FA verified
  const newToken = createToken(user, req, res, true);
  await refreshToken(user, req, res);

  res.status(200).json({
    status: "success",
    token: newToken,
    message: "Backup code used successfully",
  });
});

// 2FA Recovery OTP send via email
exports.requestRecoveryOTP = catchAsync(async (req, res, next) => {
  const user = req.user;

  if (!user.twoFactorEnabled) {
    return next(new ApiError("2FA is not enabled for this account", 400));
  }

  // Prevent spam: Allow only one requset per minute
  const oneMinuteAgo = new Date(Date.now() - 60 * 1000);
  if (user.twoFactorLastRequest && oneMinuteAgo < user.twoFactorLastRequest) {
    // 429 Too many requset
    return next(new ApiError("Please wait before requesting another OTP", 429));
  }

  // Genrat OTP
  const otp = Math.floor(100000 + Math.random() * 900000).toString();

  // Store otp in db
  user.twoFactorRecoveryOTP = user.hashBackupCode(otp);
  user.twoFactorRecoveryExpires = new Date(Date.now() + 5 * 60 * 1000); // Valid for 5 minutes
  user.twoFactorLastRequest = new Date(); // Track last request time
  await user.save({ validateBeforeSave: false });

  // Send OTP via email
  try {
    await new Email(user, otp).sendTwoFactorRecovery();
    res
      .status(200)
      .json({ status: "success", message: "OTP sent to your email" });
  } catch (err) {
    user.twoFactorRecoveryOTP = undefined;
    user.twoFactorRecoveryExpires = undefined;
    user.twoFactorLastRequest = undefined;

    await user.save({ validateBeforeSave: false });
    console.error("Error sending email:", err);
    return next(new ApiError("Failed to send email. Try again letter!", 500));
  }
});
exports.verifyRecoveryOTP = catchAsync(async (req, res, next) => {
  const { otp } = req.body;
  const user = req.user;

  if (!user.twoFactorEnabled) {
    return next(new ApiError("2FA is not enabled for this account", 400));
  }

  // Check expiration
  if (
    !user.twoFactorRecoveryExpires ||
    user.twoFactorRecoveryExpires < new Date()
  ) {
    return next(new ApiError("OTP expired. Request a new one", 401));
  }

  // Verify OTP
  if (user.hashBackupCode(otp) !== user.twoFactorRecoveryOTP) {
    return next(new ApiError("Invalid OTP", 401));
  }

  // Clear OTP after successful
  user.twoFactorRecoveryOTP = undefined;
  user.twoFactorRecoveryExpires = undefined;
  user.twoFactorLastRequest = undefined;
  await user.save({ validateBeforeSave: true });

  // Genrate new Token with 2FA verified
  const token = createToken(user, req, res, true);
  await refreshToken(user, req, res);

  res.status(200).json({
    status: "success",
    token,
    message: "2FA bypassed using recovery OTP",
  });
});

// 2FA Recovery OTP send via SMS
exports.requestRecoverySMS = catchAsync(async (req, res, next) => {
  const user = req.user;

  if (!user.twoFactorEnabled) {
    return next(new ApiError("2FA is not enabled for this account", 400));
  }

  if (!user.phone) {
    return next(
      new ApiError("No phone number registered for this account", 400)
    );
  }

  // Prevernt spam: Allow only one requset per time
  const oneMinuteAgo = new Date(Date.now() - 60 * 1000);
  if (user.twoFactorLastRequest && oneMinuteAgo < user.twoFactorLastRequest) {
    // 429 Too many requset
    return next(new ApiError("Please wait before requesting another OTP", 429));
  }

  // Genrate OTP
  const otp = Math.floor(100000 + Math.random() * 900000).toString();

  // Store OTP
  user.twoFactorRecoveryOTP = user.hashBackupCode(otp);
  user.twoFactorRecoveryExpires = new Date(Date.now() + 5 * 60 * 1000); // Valid for 5 min
  user.twoFactorLastRequest = new Date();
  await user.save({ validateBeforeSave: false });

  try {
    await new SMS(user, otp).sendTwoFactorRecovery();
    res.status(200).json({
      status: "success",
      message: "OTP sent via SMS",
    });
  } catch (err) {
    user.twoFactorRecoveryOTP = undefined;
    user.twoFactorRecoveryExpires = undefined;
    user.twoFactorLastRequest = undefined;
    await user.save({ validateBeforeSave: false });

    console.error("Error sending email:", err);
    return next(new ApiError("Failed to send SMS. Try again letter!", 500));
  }
});
exports.verifyRecoverySMS = catchAsync(async (req, res, next) => {
  const { otp } = req.body;
  const user = req.user;

  if (!user.twoFactorEnabled) {
    return next(new ApiError("2FA is not enabled for this account", 400));
  }

  // Check expiration
  if (
    user.twoFactorRecoveryExpires &&
    user.twoFactorRecoveryExpires < new Date()
  ) {
    return next(new ApiError("OTP expired. Request a new one", 401));
  }

  // Verify OTP
  if (user.hashBackupCode(otp) !== user.twoFactorRecoveryOTP) {
    return next(new ApiError("Invalid OTP", 401));
  }

  // Clear OTP
  user.twoFactorRecoveryOTP = undefined;
  user.twoFactorRecoveryExpires = undefined;
  user.twoFactorLastRequest = undefined;
  await user.save({ validateBeforeSave: true });

  // Genrate JWT with 2FA verified
  const token = createToken(user, req, res, true);
  await refreshToken(user, req, res);

  res.status(200).json({
    status: "success",
    token,
    message: "2FA bypassed using recovery SMS",
  });
});
