const mongoose = require("mongoose");

const connectDB = async () => {
    const db = mongoose.connect('mongodb://127.0.0.1:27017/authentication');
    console.log("Connected to Mongodb");
    return db;
}

module.exports = connectDB;

