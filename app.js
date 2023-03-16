require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose")
const GoogleStrategy = require("passport-google-oauth20").Strategy; 

const port = 3000 || process.env.PORT;

const app = express();

app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(bodyParser.urlencoded({
    extended: true
}));

app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://127.0.0.1:27017/userDB");

const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    googleId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user.id);
  });

passport.deserializeUser(function(id, done) {
        User.findById(id).then(user=>{
            done(null, user);
        }).catch((err)=>{ return done(err); });
  });

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, done) {
    console.log(profile)
    User.findOne({
        googleId: profile.id 
    }).then(function(user) {
        if (!user) {
            user = new User({
                googleId: profile.id,
                username: profile.displayName
            });
            user.save();
        }
        return done(null, user);
    }).catch((err) => {
        return done(err);
    })
}
));

app.get("/", function(req, res){
    res.render("home")
})

app.get("/auth/google", passport.authenticate("google", { scope: ["profile"] })
);

app.get('/auth/google/secrets', 
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect("/secrets");
  });

app.get("/login", function(req, res){   
    res.render("login");
})

app.get("/register", function(req, res){
    res.render("register");
});

app.get("/secrets", function(req, res){
    User.find({"secret": {$ne: null}}).then((foundUsers) => {
        if(foundUsers) {
            res.render("secrets", {usersWithSecrets: foundUsers})
        } 
    })
})

app.get("/submit", function(req, res){
    if(req.isAuthenticated()){
        res.render("submit");
    } else {
        res.redirect("/login");
    }
})

app.post("/submit", function(req, res){
    const submittedSecret = req.body.secret;

    User.findById(req.user.id).then((foundUser)=> {
        if(foundUser) {
            foundUser.secret = submittedSecret;
            foundUser.save().then(()=>{
                res.redirect("/secrets");
            })
        }
    });
})

app.get("/logout", function(req, res){
    req.logout(function(err){
        if(err) {
            console.log(err);
        }
    });
    res.redirect("/");
})

app.post("/register", function(req, res){
    User.register({username: req.body.username}, req.body.password, function(err, user){
        if(err) {
            console.log(err);
            res.render("/register");
        } else {
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            })
        }
    });
})

app.post("/login", function(req, res){
    
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.logIn(user, function(err){
        if(err) {
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            })
        }
    })
})


app.listen(port, function(){
    console.log("Server started on port " + port);
})