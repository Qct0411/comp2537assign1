const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const MongoStore = require('connect-mongo');
require('dotenv').config();

const app = express();

const Joi = require("joi");
const { database } = require('./dbconnection');

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
//var numPageHits  = 0;

app.get('/', (req, res) => {
    if (!req.session.authenticated) {
        var html = `<h1>Home Page</h1>
                    <form action='/login' method='get'>  
                    <button>Login</button><br/>
                    </form>
                    <form action='/signup' method='get'>  
                    <button>Sign up</button><br/>
                    </form>`;
        res.send(html);
    } else {
        var html = `<h1>Home Page</h1>
                    <p>Welcome ${req.session.username}!</p>
                    <form action='/members' method='get'>
                    <button>members</button><br/>
                    </form>
                    <form action='/logout' method='post'>
                    <button>Logout</button><br/>
                    </form>`;
        console.log(req.session.username);
        res.send(html);
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
        var html = `<h1>Members Page</h1>
                    <p>Welcome ${req.session.username}!</p>
                    <img src='${picname}' width='300'><br/>
                    <form action='/logout' method='post'>
                    <button>Logout</button><br/>
                    </form>`;
        res.send(html);
    }
}); 

app.get('/login', (req, res) => {
    var html = `<p>login Page</p>
                <form action='/loginsubmit' method='post'>
                <input type='text' name='email' placeholder='email'><br/>
                <input type='password' name='password' placeholder='password'><br/>  
                <button>Submit</button><br/>
                </form>`;
    res.send(html);
});

app.get('/signup', (req, res) => {
    var html = `<p>signup Page</p>
                <form action='/signupSubmit' method='post'>
                <input type='text' name='username' placeholder='username'><br/>
                <input type='text' name='email' placeholder='email'><br/>
                <input type='password' name='password' placeholder='password'><br/>  
                <button>Submit</button><br/>
                </form>`;
    res.send(html);
});

app.post('/signupSubmit', async(req, res) => {
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;
    
    if (!username) {
        res.send(`<p>username required</p><br/>
                  <a href='/signup'>Back to signup</a>`);
    } else if(!email) {
        res.send(`<p>email required</p><br/>
                    <a href='/signup'>Back to signup</a>`);
    } else if(!password) {
        res.send(`<p>password required</p><br/>
                    <a href='/signup'>Back to signup</a>`);
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
        await userCollection.insertOne({username: username, email: email, password: encryptedPassword});
        console.log("inserted");
        req.session.authenticated = true;
        req.session.email = email;
        req.session.username = username;
        req.session.cookie.maxAge = expireTime;
        res.redirect('/members');
        //res.send("user created, welcome " + username);
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
    const result = await userCollection.find({email: email}).project({email: 1, password: 1, username: 1, _id: 1}).toArray();
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
        req.session.cookie.maxAge = expireTime;
        res.redirect('/');
    } else {
        console.log("password mismatch");
        res.send(`<p>User and password not found</p><br/>
                    <a href='/login'>Back to login</a>`);
    }
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
	res.status(404);
	res.send("Page not found - 404");
})

app.listen(port, () => {
    console.log("Server running on port: " + port);
});

