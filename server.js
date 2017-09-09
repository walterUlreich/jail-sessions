var bodyParser = require('body-parser');
var mongoose = require('mongoose');
var bcrypt = require('bcryptjs');
var express = require('express');
var sessions = require("client-sessions");

var app = express();
app.use(express.static('./public'))

var sessionsMiddleware = sessions({
    cookieName: 'auth-cookie',  // front-end cookie name
    secret: 'DR@G0N$',        // the encryption password : keep this safe
    requestKey: 'session',    // we can access our sessions at req.session,
    duration: (86400 * 1000) * 7, // one week in milliseconds
    cookie: {
        ephemeral: false,     // when true, cookie expires when browser is closed
        httpOnly: true,       // when true, the cookie is not accesbile via front-end JavaScript
        secure: false         // when true, cookie will only be read when sent over HTTPS
    }
}) // encrypted cookies!
app.use(sessionsMiddleware)

app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

/** Database setup **/
mongoose.connect('mongodb://localhost/jail', function(err) {
    if( err ) {
        console.error('Could not connect to the Mongo Jailhouse!');
    } else {
        console.info("Connected to the Jailhouse!");
    }
});

var User = mongoose.model('user', mongoose.Schema({
    username : { type: String, required: true, unique: true },
    password : { type: String, required: true },
    role     : { type: String, required: true }
}));

/*
app.get('/example', protected, function(req, res){ res.send('example'); });

function protected(req, res, next) {
    if( req.session.user.role === 'someRole' ) {
        // do something and call next()
    } else {
        // send down a forbidden response (status code 403)
    }
}
*/

var checkIfAlice = function(req, res, next) {
  User.findOne({_id: req.session.uid}, function(err, user){
      console.log(user.role)
      if (user.role === 'warden') {
        res.sendFile('./html/wardens-office.html', {root:'./public'});
      } else {
        res.redirect('/')
      }
  })
}

var lobbyCheck = function(req, res, next) {
  User.findOne({_id: req.session.uid}, function(err, user){
      console.log(user.role)
      if (user.role === 'warden' || user.role === 'guard' || user.role === 'visitor') {
        res.sendFile('./html/lobby.html', {root:'./public'});
      } else {
        res.redirect('/')
      }
  })
}

var visitorsLoungeCheck = function(req, res, next) {
  User.findOne({_id: req.session.uid}, function(err, user){
      console.log(user.role)
      if (user.role === 'warden' || user.role === 'guard' || user.role === 'visitor') {
        res.sendFile('./html/visitors-lounge.html', {root:'./public'});
      } else {
        res.redirect('/')
      }
  })
}

var cafeteriaCheck = function(req, res, next) {
  User.findOne({_id: req.session.uid}, function(err, user){
      console.log(user.role)
      if (user.role !== 'visitor') {
        res.sendFile('./html/cafeteria.html', {root:'./public'});
      } else {
        res.redirect('/')
      }
  })
}

var eveCellCheck = function(req, res, next) {
  User.findOne({_id: req.session.uid}, function(err, user){
      console.log(user.role)
      if (user.username !== 'carlos' && user.username !== 'mallory') {
        res.sendFile('./html/cell-e.html', {root:'./public'});
      } else {
        res.redirect('/')
      }
  })
}

var malloryCellCheck = function(req, res, next) {
  User.findOne({_id: req.session.uid}, function(err, user){
      console.log(user.role)
      if (user.username !== 'carlos' && user.username !== 'eve') {
        res.sendFile('./html/cell-m.html', {root:'./public'});
      } else {
        res.redirect('/')
      }
  })
}


app.get('/', function(req, res){
    res.sendFile('./html/login.html', {root:'./public'});
});

app.get('/jail', function(req, res, next){
    res.sendFile('./html/jail.html', {root:'./public'});
});

app.get('/lobby', lobbyCheck, function(req, res, next){
  console.log(req.session)
});

app.get('/visitors-lounge', visitorsLoungeCheck, function(req, res, next){
  console.log(req.session)
});

app.get('/cafeteria', cafeteriaCheck, function(req, res, next){
  console.log(req.session)
});

app.get('/wardens-office', checkIfAlice, function(req, res, next){
  console.log(req.session)
});

app.get('/cell-e', eveCellCheck, function(req, res, next){
  console.log(req.session)
});

app.get('/cell-m', malloryCellCheck, function(req, res, next){
  console.log(req.session)
});

app.get('/me', function(req, res){
    User.findOne({_id: req.session.uid}, function(err, user){
        res.send(user)
    })
})

app.post('/login', function(req, res) { // form post submission
    console.info('auth.login.payload:', req.body);

    User.findOne({ username: req.body.username }, function(err, user) {
        if( err) {
            console.log('MongoDB error:', err);
            res.status(500).send("failed to find user")
        }
        else if( !user ) {
            console.log('No user found!');
            res.status(403).send("<h1>Login failed</h1>");
        } else {
            console.log('auth.login.user', user);
            // at this point, user.password is hashed!
            bcrypt.compare(req.body.password, user.password, function(bcryptErr, matched) {
                // matched will be === true || false
                if( bcryptErr ) {
                    console.error('MongoDB error:', bcryptErr);
                    res.status(500).send("mongodb error");
                } else if ( !matched ) {
                    // forbidden, bad password
                    console.warn('Password did not match!');
                    res.status(403).send("failed to log in");
                } else {
                    req.session.uid = user._id; // this is what keeps our user session on the backend!
                    res.send({ success: 'Login success' }); // send a success message
                }
            });
        }
    });
});



app.listen(8080)
