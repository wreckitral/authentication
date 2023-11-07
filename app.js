require("dotenv").config();
const express = require("express");
const cors = require("cors");
const morgan = require("morgan");
const connectDB = require("./database/database");
const errorHandlerMiddleware = require("./middlewares/error-handler");

const route = require("./routes/route");

const app = express();
const PORT = process.env.PORT;

console.log(process.env.NODE_ENV);

app.use(express.json());
app.use(cors());
app.use(morgan("tiny"));
app.disable("x-powered-by"); 

app.use(route); 

app.use(errorHandlerMiddleware); // error handling middleware

connectDB().then(() => {
  try {
    app.listen(PORT, () => {
      console.log(`Listening on Port ${PORT}`);
    });
  } catch (error) {
    console.log(error);
  }
}).catch(error => {
    console.log(error);
})
