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
    phone: String,
    profileImage: String,
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
    passwordChangedAt: Date,
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
  return await bcrypt.compare(candidatePassword, userPassword);
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
const User = mongoose.model("User", userSchema);
module.exports = User;
