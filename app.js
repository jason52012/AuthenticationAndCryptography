require("dotenv").config();
const express = require("express");
const app = express();
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const User = require("./models/user");
const bcrypt = require("bcrypt");
const session = require("express-session");
const saltRounds = 10; // it will be executed hoe many times => 2^10 = 1024

app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static("public"));

app.use(
  session({
    secret: process.env.SECRET,
    resave: false,
    saveUnintialized: false, //false =>  must go to specific page to use session => generate session object
  })
);

app.set("view engine", "ejs");

let isVerified = (req, res, next) => {
  if (!req.session.verified) {
    res.redirect("/login");
  } else {
    next();
  }
};
// connect to mongoDB
mongoose
  .connect("mongodb://localhost:27017/exampledb", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("Connected to MongoDb"))
  .catch((err) => {
    console.log("Connected fail");
    console.err(err);
  });

app.get("/", (req, res) => {
  res.send("Home page");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.post("/login", async (req, res, next) => {
  let { username, password } = req.body;
  try {
    let user = await User.findOne({ username });
    if (user) {
      // Load hash from your password DB.
      bcrypt.compare(password, user.password, function (err, result) {
        if (err) {
          next(err);
        }
        if (result === true) {
          req.session.verified = true;
          res.render("secret.ejs");
        } else {
          res.send("username or password not correct");
        }
      });
    }
  } catch (err) {
    next(err);
  }
});

app.get("/signup", (req, res) => {
  res.render("signup.ejs");
});

app.post("/signup", async (req, res, next) => {
  let { username, password } = req.body;

  try {
    let foundUser = await User.find({ username });

    if (foundUser) {
      res.send("this username cannot be saved");
    } else {
      bcrypt.genSalt(saltRounds, function (err, salt) {
        if (err) {
          next(err);
        }
        bcrypt.hash(password, salt, function (err, hash) {
          if (err) {
            next(err);
          }
          let newUser = new User({ username, password: hash });
          try {
            newUser.save().then(() => {
              res.send("Thanks for posting.");
            });
          } catch (err) {
            next(err);
          }
        });
      });
    }
  } catch (e) {
    next(e);
  }
});

app.get("/secret", isVerified, (req, res) => {
  res.render("secret.ejs");
});

app.listen("3000", () => {
  console.log("port 3000 is running");
});
