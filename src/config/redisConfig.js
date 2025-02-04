const redis = require("redis");

const redisClient = redis.createClient({
  password: process.env.REDIS_PASSWORD,
  socket: {
    host: process.env.REDIS_HOST,
    port: process.env.REDIS_PORT,
  },
});

const redisConnect = () => {
  redisClient
    .connect()
    .then(() => {
      console.log("Redis Client Connected.");
    })
    .catch((err) => {
      console.error("Redis Error:", err);
    });
};

module.exports = { redisClient, redisConnect };
