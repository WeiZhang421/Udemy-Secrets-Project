require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
// const encrypt = require("mongoose-encryption");
// const md5 = require("md5");
// const bcrypt = require("bcryptjs");
// const saltRounds = 10;
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.set("view engine", "ejs");

app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));

app.use(session({
    secret: "our secrets",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://127.0.0.1:27017/userDB");

const secretSchema = new mongoose.Schema({
    secret: String
});

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    facebookId: String,
    secrets: [secretSchema]
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ["password"]});

const Secret = new mongoose.model("Secret", secretSchema);
const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser((user, cb) => {
    process.nextTick(() => {
        return cb(null, {
            id: user.id,
            username: user.username,
            name: user.name
        });
    });
});
passport.deserializeUser((user, cb) => {
    process.nextTick(() => {
        return cb(null, user);
    });
});

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    passReqToCallback: true,
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(request, accessToken, refreshToken, profile, done) {
    // console.log(profile)
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return done(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_CLIENT_ID,
    clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
    callbackURL: "https://localhost:3000/auth/facebook/secrets"
  },
  function(request, accessToken, refreshToken, profile, done) {
    // console.log(profile)
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return done(err, user);
    });
  }
));

app.get("/", (req, res) => {
    res.render("home");
});

app.get("/auth/google", passport.authenticate("google", {scope: ["profile"]}));

app.get("/auth/google/secrets", 
passport.authenticate("google", 
    {successRedirect: "/secrets",
     failureRedirect: "/login"}));

app.get("/auth/facebook", passport.authenticate("facebook"));

app.get("/auth/facebook/secrets", 
passport.authenticate("facebook", 
    {successRedirect: "/secrets",
     failureRedirect: "/login"}));

app.get("/login", (req, res) => {
    res.render("login");
});

app.get("/register", (req, res) => {
    res.render("register");
});

app.get("/secrets", (req, res) => {
    Secret.find()
    .then((foundSecrets) => {
        res.render("secrets", {secrets: foundSecrets});
    })
    .catch((err) => {
        console.log(err);
    });
});

app.get("/submit", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});

app.post("/submit", (req, res) => {
    const submittedSecret = new Secret({
        secret: req.body.secret
    });
    submittedSecret.save();

    User.findById(req.user.id)
    .then((foundUser) => {
        foundUser.secrets.push(submittedSecret);
        foundUser.save();
        res.redirect("/secrets");
    })
    .catch((err) => {
        console.log(err);
    });
});

app.get("/logout", (req, res) => {
    req.logout((err) => {
        if (err) {
            return next(err);
        } else {
            res.redirect("/");
        }
    });
});

app.post("/register", (req, res) => {
    User.register({username: req.body.username}, req.body.password)
    .then((user) => {
        passport.authenticate("local")(req, res, () => {
            res.redirect("/secrets");
        });
    })
    .catch((err) => {
        res.redirect("/register");
    });
});

app.post("/login", (req, res) => {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });
    req.login(user, (err) => {
        if (err) {
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, () => {
                res.redirect("/secrets");
            });
        }
    });
});

// app.post("/register", (req, res) => {

//     const hash = bcrypt.hashSync(req.body.password, saltRounds)
//     const newUser = new User({
//         email: req.body.username,
//         password: hash
//     });  
    
//     newUser.save()
//     .then(() => {
//         res.render("secrets");
//     })
//     .catch((err) => {
//         console.log(err);
//     });  
//     // const newUser = new User({
//     //     email: req.body.username,
//     //     password: md5(req.body.password)
//     // });
// });

// app.post("/login", (req, res) => {
//     const username = req.body.username;
//     // const password = md5(req.body.password);
//     const password = req.body.password;   

//     User.findOne({email: username})
//     .then((foundUser) => {
//         if (foundUser) {
//             if(bcrypt.compareSync(password, foundUser.password)) {
//                 res.render("secrets");
//             }
//         }

//         // if (foundUser) {
//         //     if (foundUser.password === password) {
//         //         res.render("secrets");
//         //     }
//         // } 
//     })
//     .catch((err) => {
//         console.log(err);
//     });
// });

app.listen(3000, function() {
    console.log("Server started on port 3000");
});