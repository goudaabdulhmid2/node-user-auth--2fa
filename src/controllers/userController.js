const { getAll, getOne, createOne } = require("./handlerFactory");

const User = require("./../models/user");

exports.getAllUsers = getAll(User);

exports.getUser = getOne(User);

exports.createUser = createOne(User);
