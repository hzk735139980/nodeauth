var express = require('express');
var router = express.Router();
var db = require('../db');
var expressValidator = require('express-validator');
var bcrypt = require('bcrypt');
const saltRounds = 10;
var passport  = require('passport');
var LocalStrategy   = require('passport-local').Strategy;
var FacebookStrategy = require('passport-facebook');

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index');
});

router.get('/signup', function(req, res, next) {
  res.render('signup', {errors: false});
});

router.get('/login', function(req, res, next) {
  res.render('login', {errors: false});
});

router.get('/logout', function(req, res, next) {
  req.logout();
  res.redirect('/');
});

router.post('/login', 
  passport.authenticate('local', { 
    successRedirect: '/profile',
    failureRedirect: '/login'
}));

router.get('/profile', isLoggedIn, function(req, res, next){
  res.render('profile', {user: req.user});
});

router.post('/signup', function(req, res){
   // Form Validation
  req.checkBody('username', 'Username field is required').notEmpty();
  req.checkBody('username', 'Username must be 4-30 characters size long, please try again.').len(4, 30);
  req.checkBody('password', 'Password field is required').notEmpty();
  req.checkBody('password', 'password must be 4-30 characters size long, please try again.').len(4, 60);
  req.checkBody('repassword', 'Passwords do not match').equals(req.body.password);

  // Check for errors
  var errors = req.validationErrors();
  
  if(errors){
    console.log(JSON.stringify(errors));
    res.render('signup', {errors: errors});
  }else{
    const username = req.body.username;
    const password = req.body.password;
    bcrypt.hash(password, saltRounds, function(err, hash) {
      db.query("INSERT INTO users ( username, password ) values (?,?)", [username, hash], function(error, result, field){
        if (error) throw error;
        const user_id = result.insertId;
        req.login(user_id, function(err){
          if (err) {  throw err; }
          res.redirect('/profile');
        })
      });
    });

  }
})

passport.serializeUser(function(user, done) {
  done(null, user);
});
 
passport.deserializeUser(function(id, done) {
  db.query("SELECT * FROM users WHERE id = ? ",[id], function(err, result, field){
    done(err, result[0]);
  });
});

passport.use(new LocalStrategy(
  function(username, password, done) {
    db.query("SELECT id, password FROM users WHERE username = ?", [username], function(err, result, field){
      if(err){ return done(err)};
      if(!result){
        return done(err, false);
      }
      const hash = result[0].password.toString();
      bcrypt.compare(password, hash, function(err, res) {
        if(res){
          return done(err, result[0].id);
        }else{
          return done(err, false);
        }
      })
    })
}));
router.get('/auth/facebook',
  passport.authenticate('facebook'));

router.get('/auth/facebook/callback',
  passport.authenticate('facebook', { 
    successRedirect: '/profile',
    failureRedirect: '/login' 
}));

//facebook Strategy
const FACEBOOK_APP_ID = '183535639002169';
const FACEBOOK_APP_SECRET = '7c56b87b29bfbd6152b53bfa9f258ef3';
passport.use(new FacebookStrategy({
  clientID: FACEBOOK_APP_ID,
  clientSecret: FACEBOOK_APP_SECRET,
  callbackURL: "http://localhost:3000/auth/facebook/callback",
  profileFields: ['id', 'name']
},
function(accessToken, refreshToken, profile, cb) {
  db.query("SELECT id FROM users WHERE username = ?", [profile.name.givenName], function(err, result, field){
    if (err) throw err;
    if(result.length == 0){
        db.query("INSERT INTO users ( username, password ) values (?,?)", [profile.name.givenName, 'facebook'], function(error, result, field){
          if (error) throw error;
          const user_id = profile.id;
          return cb(err, user_id);
        });
    }else{
      return cb(err, result[0].id);
    }
  });
}));

// authentication middleware
function isLoggedIn(req, res, next) {

	if (req.isAuthenticated())
		return next();

	res.redirect('/login');
}

module.exports = router;
