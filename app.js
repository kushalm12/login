//jshint esversion:6
require('dotenv').config();

const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const app = express();
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
app.use(express.static("public"));
app.set('view engine','ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));


app.use(session({
  secret: process.env.SECRET,
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    useCreateIndex: true,
    useFindAndModify: false,
  });


  const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    username: String
  });

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);


  const User = new mongoose.model("User",userSchema);

  passport.use(User.createStrategy());

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
  },
  function(accessToken, refreshToken, profile,cb) {
    console.log(profile);
    User.findOrCreate(
    {   googleId: profile.id,
        username: profile.emails[0].value
    },
    function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/",function(req,res){
  res.render("home");
});

app.get("/login",function(req,res){
  res.render("login");
});

app.get("/register",function(req,res){
  res.render("register");
});

app.get("/secrets",function(req,res){
  if(req.isAuthenticated()){
    res.render("secrets");
  }else{
    res.render("login");
  }
});

app.get("/auth/google", passport.authenticate('google', {

    scope: ['profile','email']

}));

app.get('/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });



app.post("/register",function(req,res){

      // Store hash in your password DB.
      User.register({username: req.body.username},req.body.password,function(err,user){
        if(err){
          console.log(err);
          res.redirect("/register");
        }
        else{
          passport.authenticate("local")(req,res,function(){
              res.redirect("/secrets");
          });
        }
      });




});

app.post("/login",function(req,res){

  User.findOne({username: req.body.username}, function(err, foundUser){

    if(foundUser){
    const user = new User({
      username: req.body.username,
      password: req.body.password
    });

      passport.authenticate("local", function(err, user){
        if(err){
          console.log(err);
        } else {

          if(user){
            req.login(user, function(err){
            res.redirect("/secrets");
            });
          } else {
            res.redirect("/login");
          }
        }
      })(req, res);
    } else {
      res.redirect("/login");
    }
  });


});

app.get("/logout",function(req,res){
  req.logout();
  res.redirect("/");
});

app.listen(3000,function(){
  console.log("Server started on port 3000");
});
