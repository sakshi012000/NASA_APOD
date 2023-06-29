require('dotenv').config();
const express = require("express");
const path = require("path");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const passport = require('passport');
const app = express();
const bodyParser = require('body-parser');
// const hbs = require("hbs")
const LogInCollection = require("./db/conn");
const Register = require('./models/register');
const bcrypt = require('bcryptjs');
const port = process.env.PORT || 5000
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const exp = require('constants');
const auth = require("./middleware/auth")
const axios = require('axios');
// const fetch = require('node-fetch');
const fetch = require('isomorphic-fetch');
const cheerio = require('cheerio');

app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: false }));
app.use(bodyParser.urlencoded({ extended: false }));


const tempelatePath = path.join(__dirname, '../templates')
const publicPath = path.join(__dirname, '../public')
console.log(publicPath);

app.set('view engine', 'hbs')
app.set('views', tempelatePath)
app.use(express.static(publicPath))


app.get('/signup', (req, res) => {
    res.render('signup')
});

app.get('/', (req, res) => {
    res.render('home')
});

app.get('/apod', async (req, res) => {
    try {
      const url = `https://apod.nasa.gov/apod/astropix.html`;
  
      const response = await fetch(url);
      const html = await response.text();
      const $ = cheerio.load(html);
  
      const imageSrc = $('img').attr('src');
  
      if (imageSrc) {
        res.send(`<img src="https://apod.nasa.gov/apod/${imageSrc}" alt="NASA APOD">`);
      } else {
        res.send('No image found.');
      }
    } catch (error) {
      console.error('Error:', error);
      res.status(500).send('An error occurred.');
    }
  });


app.get('/login', (req, res) => {
    res.render('login')
});


// Registering user
app.post('/signup', async (req, res) => {

    try {

        const email = req.body.email;
        const password = req.body.password;
        const cpassword = req.body.cpassword;
        
        const existingUser = await Register.findOne({email:email});
        if (existingUser) {
            return res.status(409).render('signup', { successMessage: 'Email already registered!!' }); 
        }

        if(password === cpassword){
            
            const registerUser = new Register({
                email : req.body.email,
                password : password,
                cpassword : cpassword
            })
        
            const token = await registerUser.generateAuthToken();
            // console.log('Token part ' + token);            

            res.cookie('jwt', token, {
                expires:new Date(Date.now() + 600000),
                httpOnly:true
            }); 


            // console.log('cookie' + cookie);

            const registered = await registerUser.save();
            res.render('signup', { successMessage: 'Registration Successful!' });
            // res.status(201).render('home');


        }else{
            console.log("P not maatch");
            // res.send("Password not matching");
            res.render('signup', { successMessage: 'Password and Confim password are different' });
          }
        
    } catch (error) {
        console.error('Error signing up:', error);
        res.status(500).json({ error: 'Failed to sign up' });
    }
})

  
app.post('/login', async (req, res) => {

    try {
        
        const email = req.body.email;
        const password = req.body.password;
        // console.log(`${email} amd ${password}`)

        const useremail = await Register.findOne({email:email});
       
        if (!useremail) {
            return res.status(401).render('login', { successMessage: 'Invalid credentials' });
          }

        const isMatched = await bcrypt.compare(password, useremail.password);

        // const token = await useremail.generateAuthToken();
        
        // res.cookie('jwt', token, {
        //     expires:new Date(Date.now() + 600000),
        //     httpOnly:true
        // }); 

        if(isMatched){

            const token = await useremail.generateAuthToken();

            res.cookie('jwt', token, {
                expires: new Date(Date.now() + 600000),
                httpOnly: true
            });

            console.log('Reached login part');
            res.redirect('/apod');
            console.log('After apod check');

        }else{
            // res.send('Invalid credentials');
            return res.status(401).render('login', { successMessage: 'Invalid credentials' });

          }

    } catch (error) {
      return res.status(401).render('login', { successMessage: 'Invalid credentials' });
    }
});

 
// Configure environment variables
const googleClientID = process.env.GOOGLE_CLIENT_ID || '372459403922-u46ved0n16b804hs1dn01oshan4u57du.apps.googleusercontent.com';
const googleClientSecret = process.env.GOOGLE_CLIENT_SECRET || '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';
const sessionSecret = process.env.SESSION_SECRET || 'MySecretKey123';

// Configure Express middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// Configure session middleware
app.use(session({
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false
}));

// Initialize Passport.js
app.use(passport.initialize());
app.use(passport.session());

// Configure Passport.js to use Google OAuth strategy
passport.use(new GoogleStrategy({
  clientID: googleClientID,
  clientSecret: googleClientSecret,
  callbackURL: '/auth/google/callback'
}, (accessToken, refreshToken, profile, done) => {
  // Handle the user profile and perform any necessary authentication logic
  // This function is called when a user successfully authenticates with Google
  // You can customize it according to your application's requirements
  // For example, you might want to save the user profile to a database
  return done(null, profile);
}));

// Serialize and deserialize user
passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

// Route for initiating the Google authentication flow
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// Callback route for receiving the Google authentication response
app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    // Successful authentication, redirect to the home page or a success page
    res.redirect('/home');
  }
);

// Route for logging out
app.get('/logout', (req, res) => {
  req.logout();
  res.redirect('/login'); // Redirect to the login page after logout
});

// Sample protected route
app.get('/home', (req, res) => {
  if (req.isAuthenticated()) {
    // User is authenticated, render the home page or a protected resource
    res.send('Welcome to the home page!');
  } else {
    // User is not authenticated, redirect to the login page
    res.redirect('/login');
  }
});

// Sample login route
app.get('/login', (req, res) => {
  res.send('Please login');
});


app.on('error', (error) => {
    console.error('Server error:', error);
  });
  app.listen(port, '0.0.0.0', () => {
    console.log(`Server is running on port ${port}`);
  });
  


