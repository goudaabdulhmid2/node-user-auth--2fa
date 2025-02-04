class ApiFetures {
  constructor(query, reqQueryString) {
    this.query = query;
    this.reqQueryString = reqQueryString;
  }

  filter() {
    const queryObject = { ...this.reqQueryString };
    const excludedFields = ["sort", "page", "limit", "fields", "keyword"];

    excludedFields.forEach((el) => delete queryObject[el]);

    let queryStr = JSON.stringify(queryObject);
    queryStr = queryStr.replace(
      /\b(gte|gt|lt|lte|)\b/g,
      (match) => `$${match}`
    );

    this.query = this.query.find(JSON.parse(queryStr));
    return this;
  }

  sort() {
    if (this.reqQueryString.sort) {
      const sortBy = this.reqQueryString.sort.split(",").join(" ");
      this.query = this.query.sort(sortBy);
    } else {
      this.query = this.query.sort("-createdAt");
    }

    return this;
  }

  limitFields() {
    if (this.reqQueryString.fields) {
      const fields = this.reqQueryString.fields.split(",").join(" ");
      this.query = this.query.select(fields);
    } else {
      this.query = this.query.select("-__v");
    }

    return this;
  }

  paginate(countDocuments) {
    const page = this.reqQueryString.page * 1 || 1;
    const limit = this.reqQueryString.limit * 1 || 50;
    const skip = (page - 1) * limit;
    const endIndex = page * limit;

    const pagination = {};
    pagination.page = page;
    pagination.limit = limit;
    pagination.numberOfpages = Math.ceil(countDocuments / limit);

    if (endIndex < countDocuments) {
      pagination.nextPage = page + 1;
    }

    if (skip > 0) {
      pagination.prevPage = page - 1;
    }

    this.query = this.query.skip(skip).limit(limit);
    this.paginationResult = pagination;

    return this;
  }

  keyWordSearch(modelName) {
    if (this.reqQueryString.keyword) {
      const keyword = this.reqQueryString.keyword.trim();
      const query = {
        $or: [
          {
            name: { $regex: keyword, $options: "i" },
          },
        ],
      };
      this.query = this.query.find(query);
    }
    return this;
  }
}

module.exports = ApiFetures;
