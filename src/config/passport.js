const passport = require("passport");
const FacebookStrategy = require("passport-facebook").Strategy;
const GoogleStrategy = require("passport-google-oauth20").Strategy;

const User = require("../models/user");
const ApiError = require("../utlis/ApiError");

// Genric OAuth handler
const handleOAuthUser = async ({
  providerName,
  providerId,
  providerIdField,
  email,
  name,
  done,
}) => {
  try {
    let user;

    // Try to find user by email or provider ID
    if (email) user = await User.findOne({ email });
    if (!user) user = await User.findOne({ [providerIdField]: providerId });

    // Check for email collision with different provider
    if (user && user.provider !== "local" && user.provider !== providerName) {
      return done(
        new ApiError("Email already registered with another provider", 409),
        null
      );
    }

    // Update provider info if missing
    if (user) {
      if (!user[providerIdField]) {
        user = await User.findByIdAndUpdate(
          user._id,
          {
            [providerIdField]: providerId,
            provider: providerName,
          },
          {
            new: true,
          }
        );
      }
      return done(null, user);
    }

    // Create new user
    user = await User.create({
      name,
      email: email || `${providerId}@${providerName}.com`,
      [providerIdField]: providerId,
      provider: providerName,
    });

    return done(null, user);
  } catch (err) {
    return done(new ApiError(`${providerName} login failed`, 401), null);
  }
};

// Strategy configuration helper
const configureStrategy = (Strategy, config, handler) => {
  passport.use(new Strategy(config, handler));
};

// Facbook configuration
configureStrategy(
  FacebookStrategy,
  {
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: process.env.FACEBOOK_CALLBACK_URL,
    profileFields: ["id", "emails", "name"],
  },
  async (accessToken, refreshToken, profile, done) => {
    const email = profile.emails?.[0]?.value || `${profile.id}@facebook.com`;
    const name = `${profile.name?.givenName || ""} ${profile.name?.familyName || ""}`;

    await handleOAuthUser({
      providerName: "facebook",
      providerId: profile.id,
      providerIdField: "facebookId",
      email,
      name,
      done,
    });
  }
);

// Google configuration
configureStrategy(
  GoogleStrategy,
  {
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL,
    scope: ["profile", "email"],
  },
  async (accessToken, refreshToken, profile, done) => {
    const email = profile.emails?.[0]?.value;
    const name = profile.displayName;

    await handleOAuthUser({
      providerName: "google",
      providerId: profile.id,
      providerIdField: "googleId",
      email,
      name,
      done,
    });
  }
);

module.exports = passport;
