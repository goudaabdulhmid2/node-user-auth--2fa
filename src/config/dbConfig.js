const mongoose = require("mongoose");

const dbUrl = process.env.DATABASE.replace(
  "<PASSWORD>",
  process.env.DATABASE_PASSWORD
);

const DB = () => {
  mongoose
    .connect(dbUrl)
    .then(() => {
      console.log("DB connections successful!");
    })
    .catch((err) => {
      console.log(`Errro ${err}`);
    });
};

module.exports = DB;
