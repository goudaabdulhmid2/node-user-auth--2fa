const mongoose = require("mongoose");
const slugify = require("slugify");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      trim: true,
      required: [true, "Name is required"],
      maxlength: [100, "Name cannot exceed 100 characters"],
    },
    slug: String,
    facebookId: {
      type: String,
      unique: [true, "FacebookID must be unique"],
      sparse: true,
    },
    googleId: {
      type: String,
      unique: [true, "GoogleID must be unique"],
      sparse: true,
    },
    provider: {
      type: String,
      enum: ["google", "facebook", "local"],
      default: "local",
    },
    email: {
      type: String,
      required: [true, "Email is required"],
      unique: [true, "Email must be unique"],
      lowercase: true,
      trim: true,
    },
    gender: {
      required: true,
      type: String,
      enum: ["male", "female", "other", "prefer not to say"],
    },
    brithdate: {
      type: Date,
      required: [true, "Brithdate is required"],
    },
    age: {
      type: Number,
      min: [18, "You must be at least 18 years old."],
    },
    phone: String,
    profileImage: {
      type: String,
      default: "user-profile-default-image.png",
    },
    password: {
      type: String,
      required: [
        function () {
          return this.provider === "local";
        },
        "Password is required",
      ],
      minlength: [8, "Password at least 8 char long"],
      select: false,
    },

    refreshToken: String,
    role: {
      type: String,
      enum: ["student", "admin"],
      default: "student",
    },
    active: {
      type: Boolean,
      default: true,
    },

    isVerified: {
      type: Boolean,
      default: false,
    },
    verificationToken: String,
    verificationTokenExpires: Date,
    emailVerifiedAt: Date,
    lastLogin: Date,
    lastLogout: Date,
    failedAttempts: { type: Number, default: 0 },
    lockUntil: Date,
    passwordChangedAt: Date,

    // Reset Password
    passwordResetCode: String,
    passwordResetExpires: Date,
    passwordResetVerify: Boolean,
    passwordResetLastRequest: Date,

    // 2FA
    twoFactorEnabled: { type: Boolean, default: false },
    twoFactorTempSecret: String, // Temporary secret before verification
    twoFactorSecret: String,
    backupCodes: [String], // Hashed backup codes
    twoFactorRecoveryOTP: String, // OTP for email/SMS fallback
    twoFactorRecoveryExpires: Date, // OTP expiration time
    twoFactorLastRequest: Date, // Track last request time
  },
  {
    timestamps: true,
    toObject: { virtuals: true },
    toJSON: { virtuals: true },
  }
);

// Slug
userSchema.pre("save", function (next) {
  const truncatedName = this.name.substring(0, 40); // Prevent long slugs
  this.slug = slugify(truncatedName, { lower: true, strict: true });
  next();
});

// Hash Password before saving
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();

  this.password = await bcrypt.hash(this.password, 12);

  next();
});

// Check password change
userSchema.pre("save", async function (next) {
  if (!this.isModified("password") || this.isNew) return next();
  this.passwordChangedAt = new Date() - 1000;
  next();
});

// Check Password
userSchema.methods.correctPassword = async function (
  candidatePassword,
  userPassword
) {
  const isCorrect = await bcrypt.compare(candidatePassword, userPassword);

  if (isCorrect) {
    await this.resetFailedAttempts(); // Reset failed attempts if correct
  } else {
    await this.increaseFailedAttempts(); // Increase failed attempts if incorrect
  }

  return isCorrect;
};

// Check if Password change after sign jwt
userSchema.methods.changedPasswordAfter = function (JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(
      this.passwordChangedAt.getTime() / 1000,
      10
    );

    return JWTTimestamp < changedTimestamp;
  }

  return false;
};

// Hash backup code before storing
userSchema.statics.hashBackupCode = function (code) {
  return crypto.createHash("sha256").update(code).digest("hex");
};

// Verify backup code
userSchema.methods.verifyBackupCode = function (code) {
  const hashedCode = this.constructor.hashBackupCode(code);
  const index = this.backupCodes.indexOf(hashedCode);
  if (index === -1) return false;

  // Remove used code
  this.backupCodes.splice(index, 1);
  return true;
};

// Brute force protection
userSchema.methods.isLocked = function () {
  if (this.lockUntil && this.lockUntil < Date.now()) {
    this.lockUntil = undefined;
    this.failedAttempts = 0;

    // Background save with proper error handling
    this.save({ validateBeforeSave: false }).catch((err) => {
      console.error("Failed to persist account unlock:", {
        userId: this._id,
        error: err.message,
      });
    });

    return false;
  }
  return this.lockUntil && this.lockUntil > Date.now();
};

userSchema.methods.increaseFailedAttempts = async function () {
  // If user is locked return nothing
  if (this.isLocked()) return this;

  // Increase failed attempts
  this.failedAttempts += 1;

  // Check if user has reached max attempts
  if (this.failedAttempts >= 5) {
    this.lockUntil = Date.now() + 1000 * 60 * 15; // 15 minutes
  }
  await this.save({ validateBeforeSave: false });
  return this;
};

userSchema.methods.resetFailedAttempts = async function () {
  this.failedAttempts = 0;
  this.lockUntil = undefined;
  await this.save({ validateBeforeSave: false });
  return this;
};

userSchema.methods.getUnlockTime = function () {
  if (!this.lockUntil) return 0;
  return Math.ceil((this.lockUntil - Date.now()) / (60 * 1000)); // Returns minutes
};

const User = mongoose.model("User", userSchema);
module.exports = User;
