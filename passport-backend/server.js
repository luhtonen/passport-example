const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const morgan = require('morgan');
const mongoose = require('mongoose');
const passport = require('passport');
const config = require('./config/database');
const User = require('./app/models/users');
const port = process.env.PORT || 8080;
const jwt = require('jwt-simple');

// get our request parameters
app.use(bodyParser.urlencoded({ extended: false}));
app.use(bodyParser.json());

// log to console
app.use(morgan('dev'));

// use the passport package in our application
app.use(passport.initialize());

// demo Route (GET http://localhost:8080)
app.get('/', (req, res) => {
  res.send('Hello! The API is at http://localhost:' + port + '/api');
});

// connect to database
mongoose.connect(config.database);

// pass passport for configuration
require('./config/passport')(passport);

// bundle our routes
const apiRoutes = express.Router();

// create a new user account (POST http://localhost:8080/api/signup)
apiRoutes.post('/signup', (req, res) => {
  if (!req.body.name || !req.body.password) {
    res.json({success: false, msg: 'Please pass name and password.'})
  } else {
    const newUser = new User({
      name: req.body.name,
      password: req.body.password
    });
    // save the user
    newUser.save(err => {
      if (err) {
        return res.json({success: false, msg: 'Username already exists.'});
      }
      res.json({success: true, msg: 'Successfully created new user.'});
    });
  }
});

// connect the api routes under /api/*
app.use('/api', apiRoutes);

// start the server
app.listen(port);
console.log('There will be dragons: http://localhost:' + port);
