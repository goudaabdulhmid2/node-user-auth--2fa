const catchAsync = require("express-async-handler");

const ApiFetures = require("./../utlis/ApiFeatures");

exports.getAll = (Model, modelName = "") =>
  catchAsync(async (req, res, next) => {
    const filter = {};
    if (req.filterObj) filter = { ...req.filterObj };

    const countDocuments = await Model.countDocuments();
    const features = new ApiFetures(Model.find(filter), req.query)
      .filter()
      .sort()
      .limitFields()
      .paginate(countDocuments)
      .keyWordSearch(modelName);

    const { query, paginationResult } = features;
    const docs = await query;

    res.status(200).json({
      status: "success",
      results: docs.length,
      paginationResult,
      data: {
        data: docs,
      },
    });
  });

exports.getOne = (Model) =>
  catchAsync(async (req, res, next) => {
    const doc = await Model.findById(req.params.id);

    if (!doc) {
      return next(new AppError("No document found with that ID.", 404));
    }

    res.status(200).json({
      status: "success",
      data: {
        data: doc,
      },
    });
  });

exports.createOne = (Model) =>
  catchAsync(async (req, res, next) => {
    const newDoc = await Model.create(req.body);

    res.status(201).json({
      status: "success",
      data: {
        newDoc,
      },
    });
  });
