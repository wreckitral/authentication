const errorHandler = (err, req, res, next) => {
  const status = res.statusCode ? res.statusCode : 500; // server error
  res.status(status);
  console.log(err);
};
module.exports = errorHandler;
