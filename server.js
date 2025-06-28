// ----------------------------------------
// Github: https://github.com/MOHAMMADAMIN9/ex1B

// test user that is already in the DB: username= mohammadamin password= 1234 
// and user's profile pic is already in public/"dark knight" only to demonstrate.

// server.js
// Author: Mohammad Amin
// Date: June 2025
// Description: Node.js server with EJS and user login/register


const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const fileUpload = require("express-fileupload");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");

const app = express();
const PORT = 3000;

// configure EJS
app.set("view engine", "ejs");

// configure static folder
app.use(express.static(path.join(__dirname, "public")));

// configure session
app.use(
  session({
    secret: "mySecretKey",
    resave: false,
    saveUninitialized: true,
  })
);

// enable file uploads
app.use(fileUpload());

// enable parsing form data
app.use(express.urlencoded({ extended: true }));

// connect to SQLite
const db = new sqlite3.Database("./users.db");
// GET /register - show the registration page
app.get("/register", (req, res) => {
  res.render("register", { message: null });
});

// POST /register - handle user registration
app.post("/register", (req, res) => {
  const { username, password, email } = req.body;
  const profilePic = req.files ? req.files.profilePic : null;

  if (!username || !password || !email || !profilePic) {
    return res.render("register", { message: "All fields are required." });
  }

  // hash password
  const hashedPassword = bcrypt.hashSync(password, 10);

  // save profile picture
  const picName = `${Date.now()}_${profilePic.name}`;
  profilePic.mv(path.join(__dirname, "public", picName), (err) => {
    if (err) {
      console.error(err);
      return res.render("register", { message: "Error saving profile picture." });
    }

    // insert user into DB
    db.run(
      `INSERT INTO users (username, password, email, profilePic) VALUES (?, ?, ?, ?)`,
      [username, hashedPassword, email, picName],
      (err) => {
        if (err) {
          console.error(err);
          return res.render("register", { message: "Username already exists." });
        }
        res.redirect("/login");
      }
    );
  });
});
// GET /login - show login page
app.get("/login", (req, res) => {
  res.render("login", { message: null });
});

// POST /login - handle login
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.render("login", { message: "Username and password are required." });
  }

  db.get(
    `SELECT * FROM users WHERE username = ?`,
    [username],
    (err, user) => {
      if (err) {
        console.error(err);
        return res.render("login", { message: "Database error." });
      }
      if (!user) {
        return res.render("login", { message: "Invalid credentials." });
      }

      const match = bcrypt.compareSync(password, user.password);
      if (!match) {
        return res.render("login", { message: "Invalid credentials." });
      }

      // set session
      req.session.user = user.username;
      req.session.pic = user.profilePic;
      res.redirect("/home");
    }
  );
});

// GET /logout - destroy session
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login");
  });
});
// GET /home - protected route
app.get("/home", (req, res) => {
  if (!req.session.user) {
    return res.redirect("/login");
  }
  res.render("home", { user: req.session.user, pic: req.session.pic });
});
// start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
