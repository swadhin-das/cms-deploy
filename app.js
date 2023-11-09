require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require('mongoose');
const expressLayout = require('express-ejs-layouts');
const methodOverride = require('method-override');
const bcrypt = require("bcryptjs");
const cookieParser=require('cookie-parser')
const jwt = require('jsonwebtoken'); 
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const ejs = require('ejs');
const flash = require('connect-flash');
const Customer = require('./server/models/Customer');
const path = require('path');

const multer = require('multer');
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const uploadDir = path.resolve(__dirname, 'uploads');
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        cb(null, `${Date.now()}-${file.originalname}`);
    }
});
const filefilter = (req, file, cb) => {
    if (file.mimetype === 'image/png' || file.mimetype === 'image/jpg' 
        || file.mimetype === 'image/jpeg'){
            cb(null, true);
        }else {
            cb(null, false);
        }
}
const fileSizeFormatter = (bytes, decimal) => {
    if (bytes === 0) {
        return '0 Bytes';
    }
    const dm = decimal || 2;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'YB', 'ZB'];
    const index = Math.floor(Math.log(bytes) / Math.log(1000));
    return parseFloat((bytes / Math.pow(1000, index)).toFixed(dm)) + ' ' + sizes[index];
};

const upload = multer({storage});

const app = express();

app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(methodOverride('_method'));
app.use('/images', express.static(path.join(__dirname, 'uploads')));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(expressLayout);
app.set('layout', './layouts/main');
// Static Files
app.use(express.static('public'));
app.set("view engine", "ejs");


app.use(session({
    secret: 'secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24 * 7
    }
}));

app.use(passport.initialize());
app.use(passport.session());
// Flash Messages
app.use(flash({ sessionKeyName: 'express-flash-Message' }));

mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required:true
    },
    password: {
        type: String,
        required:true
    },
    googleId: {
        type: String
    },
    secret: {
        type: String
    },
    token: {
        type: String,
        },
    tokens: [{ 
            token: {
                type: String
            }
        }]

});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

userSchema.methods.generateAuthToken = async function () {
    try {
        console.log(this._id);
        const token = jwt.sign({ _id: this._id.toString() }, "mynameisswadhindas");
        this.tokens = this.tokens.concat({ token: token });
        await this.save();
        return token;
    } catch (error) {
        console.log("error part" + error);
    }
}

// Hash the password before saving to the database
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')){
        this.password = await bcrypt.hash(this.password,10);
    }
    next();
});
userSchema.methods.comparePassword = async function (password) {
    return bcrypt.compare(password, this.password);
};


const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function (user, done) {
    done(null, user.id);
});

passport.deserializeUser(async function (id, done) {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (err) {
        done(err);
    }
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: 'http://localhost/auth/google/constructionmanagement',
    userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo'
}, function (accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
        return cb(err, user);
    });
}));

app.get('/', (req, res) => {
    res.render("home.ejs", { layout: false });
});

app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile'] })
);

app.get('/auth/google/secrets',
    passport.authenticate('google', { failureRedirect: '/login' }),
    function (req, res) {
        res.redirect('/secrets');
    }
);

app.get('/login', (req, res) => {
    const errorMessage = req.query.error === '1' ? 'Authentication failed. Please try again.' : '';
    res.render('login.ejs', { error: errorMessage, layout: false });
});

app.get('/register', (req, res) => {
    res.render("register.ejs", { layout: false });
});

app.get('/secrets', async (req, res) => {
    try {
        const messages = await req.flash('info');
        const customers = await Customer.find({}).limit(22);
        const locals = {
            title: 'CMS',
            description: 'Construction management system',
        };

        res.render('index', { locals, messages, customers, layout: './layouts/main' });
    } catch (error) {
        console.log(error);
        res.status(500).send("Internal Server Error");
    }
});

app.get('/submit', (req, res) => {
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});

app.get("/logout", (req, res) => {
    req.logout(function (err) {
        if (err) {
            console.error(err);
        }
        res.redirect("/");
    });
});

app.get('/adminLogin', (req, res) => {
    res.render("adminLogin", { layout: false })
});

app.get("/registered", (req, res) => {
    res.render("registered", { layout: false })
});


// Registration route
app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const user = new User({ username, password: hashedPassword });
        await user.save();

        const token = user.generateAuthToken();
        console.log("the token part" + token);

        res.redirect('/registered');
    } catch (err) {
        console.error(err);
        res.redirect('/register');
    }
});

// Login route

async function hashPass(password){
    const res = await bcryptjs.hash(password,10)
    return res
}
async function compare(userPass,hashPass){
    const res = await bcryptjs.compare(userPass,hashPass)
    return res
}
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });

        if (!user) {
            return res.redirect('/login?error=1'); 
        }

        const isMatch = await user.comparePassword(password);

        if (isMatch) {
            const token = user.generateAuthToken();
            console.log("the token part: " + token);
            res.redirect('/secrets');
        } else {
            res.redirect('/login?error=1'); 
        }
    } catch (err) {
        console.error(err);
        res.redirect('/login?error=1');
    }
});

app.post("/adminLogin", async (req, res)=> {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });

        if (!user) {
            return res.redirect('/login?error=1');
        }

        const isMatch = await user.comparePassword(password);

        if (isMatch) {
            const token = user.generateAuthToken();
            console.log("the token part: " + token);
            res.redirect('/secrets');
        } else {
            res.redirect('/login?error=1'); 
        }
    } catch (err) {
        console.error(err);
        res.redirect('/login?error=1'); 
    }
});


app.use('/', require('./server/routes/customer'));

app.get('*', (req, res) =>{
    res.status(404).render('404');
});


app.post('/add',upload.single('profileImage'),async(req,res)=>{
    try {
        const { firstName, lastName, details, tel, email, profileImage } = req.body;
        if (!firstName || !lastName || !tel || !email) {
          // Handle validation errors 
          return res.status(400).send('Please fill in all required fields.');
        }
    
        const newCustomer = new Customer({
          firstName,
          lastName,
          details,
          tel,
          email,
          profileImage,
        });
    
        if (req.file) {
          // If a file was uploaded store its details in the customer object
          newCustomer.profileImage = req.file.filename;
          console.log( req.file);
        }
    
        await newCustomer.save();
        //  using connect-flash for flash messages
        req.flash('info', 'New data has been added.');
        const fileSize = fileSizeFormatter(req.file.size); 
        res.redirect('/secrets');
      } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
      }
});
  
app.listen(8000, () =>{
    console.log("Server is running on port 8000");
});

    