
require("./utils.js");
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const MongoStore = require('connect-mongo');
require('dotenv').config();
const url = require('url');

const app = express();

const Joi = require("joi");
const { database } = require('./dbconnection');

app.set('view engine', 'ejs');

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;



const port = process.env.PORT || 3020;

const node_session_secret = process.env.NODE_SESSION_SECRET; // put your secret here

const userCollection = database.db(mongodb_database).collection("users");

const expireTime = 60 * 60 * 1000; // 1 hour in milliseconds

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true
}    
));

const navLinks = [
    {name: "Home", link: "/"},
    {name: "Members", link: "/members"},
    {name: "Login", link: "/login"},
    {name: "Signup", link: "/signup"},
    {name: "Admin", link: "/admin"}
];

app.use("/",(req,res,next)=>{
    app.locals.navLinks = navLinks;
    app.locals.currentURL = url.parse(req.url).pathname;
    next();
});

function adminAuth(req,res,next){
    if(req.session.authenticated){
        if(req.session.user_type == "admin"){
            next();
        }else{
            res.status(403);
            res.render('errorMess', {mess: "You are not authorized to view this page."});
        }
    } else {
        res.redirect("/login");
    }
    
}
app.get('/', (req, res) => {
    if (!req.session.authenticated) {
        res.render('index');
    } else {
        res.render('indexWithAuth', {username: req.session.username});
    }
});

app.post('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
    } else {
        var picnum = Math.floor(Math.random() * 3);
        var picname = "";
        if (picnum == 0) {
            picname = "pic1.jpg";
        } else if (picnum == 1) {
            picname = "pic2.jpg";
        } else {
            picname = "pic3.jpg";
        }
        res.render('members', {username: req.session.username, picname: picname});
    }
}); 

app.get('/login', (req, res) => {
    res.render('login');
});

app.get('/signup', (req, res) => {
    res.render('signup');
});

app.post('/signupSubmit', async(req, res) => {
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;
    
    if (!username || !email || !password) {
        res.render('signupSubmit',{username1: username, email1: email, password1: password});
    } else {
        const schema = Joi.object({
            username: Joi.string().max(30).required(),
            email: Joi.string().email().required(),
            password: Joi.string().max(30).required()
        });
        const validation = schema.validate({username, email, password});
        if (validation.error != null) {
            console.log(validation.error);
            res.redirect('/signup');
            return;
        }
        var encryptedPassword = await bcrypt.hashSync(password, 10);
        await userCollection.insertOne({username: username, email: email, password: encryptedPassword, user_type: "user"});
        console.log("inserted");
        req.session.authenticated = true;
        req.session.email = email;
        req.session.username = username;
        req.session.cookie.maxAge = expireTime;
        res.redirect('/members');
    }
});

app.post('/loginsubmit', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.string().email().required();
    const validation = schema.validate(email);
    if (validation.error != null) {
        console.log(validation.error);
        res.redirect('/login');
        return;
    }
    const result = await userCollection.find({email: email}).project({email: 1, password: 1, username: 1,user_type:1, _id: 1}).toArray();
    console.log(result);
    if (result.length == 0) {
        console.log("email not found");
        res.redirect('/login');
        return;
    }
    if (await bcrypt.compareSync(password, result[0].password)) {
        console.log("password match");
        req.session.authenticated = true;
        req.session.email = email;
        req.session.username = result[0].username;
        req.session.user_type = result[0].user_type;
        req.session.cookie.maxAge = expireTime;
        res.redirect('/');
    } else {
        console.log("password mismatch");
        res.render('loginSubmit', {navLinks: navLinks, currentURL: url.parse(req.url).pathname});
    }
});

app.get('/admin', adminAuth, async(req, res) => {
    const result = await userCollection.find({}).project({email: 1, username: 1,user_type:1, _id: 1}).toArray();
    res.render('admin', {users: result});
});

app.post('/promote', adminAuth, async(req, res) => {
    var username = req.body.username;
    await userCollection.updateOne({username: username}, {$set: {user_type: 'admin'}});
    res.redirect('/admin');
});

app.post('/demote', adminAuth, async(req, res) => {
    var username = req.body.username;
    await userCollection.updateOne({username: username}, {$set: {user_type: 'user'}});
    res.redirect('/admin');
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
	res.status(404);
	res.render('404');
})

app.listen(port, () => {
    console.log("Server running on port: " + port);
});

