const dotenv = require("dotenv");

dotenv.config({ path: `./.env` });
const DB = require("./config/dbConfig");
const { redisClient, redisConnect } = require("./config/redisConfig");
const app = require("./app");

process.on("uncaughtException", (err) => {
  console.log(err);
  console.log("Uncaught Exceptions!");
  process.exit(1);
});

DB();

// redisConnect();

const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => {
  console.log(`APP Runing on PORT ${PORT}`);
});

process.on("unhandledRejection", (err) => {
  console.log(err);
  console.log("UNHANDLER REJECTION!");
  server.close(() => {
    process.exit(1);
  });
});

// Graceful shutdown
// process.on("SIGINT", () => {
//   redisClient.quit().then(() => {
//     console.log("Redis connection closed.");
//     mongoose.connection.close().then(() => {
//       console.log("Database connection closed.");
//       process.exit(0);
//     });
//   });
// });
