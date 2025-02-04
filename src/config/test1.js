const passport = require("passport");
const FacebookStratgy = require("passport-facebook").Strategy;
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const crypto = require("crypto");

const User = require("../models/user");
const ApiError = require("../utlis/ApiError");

// Facebook stratgy
passport.use(
  new FacebookStratgy(
    {
      clientID: process.env.FACEBOOK_APP_ID,
      clientSecret: process.env.FACEBOOK_APP_SECRET,
      callbackURL: process.env.FACEBOOK_CALLBACK_URL,
      profileFields: ["id", "emails", "name"],
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        // Retrieve email (if available) and Facebook profile ID
        const email = profile.emails[0]?.value;
        const facebookId = profile.id;
        let user;

        // If the email exists, try to find a user with that email.
        if (email) {
          user = await User.findOne({ email });
        }

        // Otherwise, check if a user with this facebookId already exists.
        if (!user) {
          user = await User.findOne({ facebookId });
        }

        if (user) {
          // Update the user document with the facebook info if needed
          if (!user.facebookId) {
            user.facebookId = facebookId;
            user.provider = "facebook";
            await user.save({ validateBeforeSave: false });
          }
          return done(null, user);
        }

        // Create a new user since one dosen't exist.
        const randomPassword = crypto.randomBytes(20).toString("hex");
        user = await User.create({
          name: `${profile.name.givenName} ${profile.name.familyName}`,
          email: email || `${facebookId}@facebook.com`, // Fallback if email not provided
          facebookId,
          provider: "facebook",
          password: randomPassword,
        });

        return done(null, user);
      } catch (err) {
        return done(new ApiError("Facebook login failed", 401), null);
      }
    }
  )
);

// Google stratgy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
      scope: ["profile", "email"],
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        // Check if user exists in your DB
        let user = await User.findOne({ email: profile.emails[0].value });

        if (user) {
          // Update the user document with the Google info if needed
          if (!user.googleId) {
            user.googleId = profile.id;
            user.provider = "google";
            await user.save({ validateBeforeSave: false });
          }
          return done(null, user);
        }

        // Create new user if not found
        const randomPassword = crypto.randomBytes(20).toString("hex");
        user = await User.create({
          name: profile.displayName,
          email: profile.emails[0].value,
          provider: "google",
          googleId: profile.id,
          password: randomPassword,
        });
        return done(null, user);
      } catch (err) {
        console.log(err);
        return done(new ApiError("Google login failed", 401), null);
      }
    }
  )
);

module.exports = passport;
