var express=require('express');
var fs=require('fs');
var bodyParser = require('body-parser');
var session =require('express-session');
var app=express(), cors = require('cors');
var db= require('./models/db');
var dbconnection = db.dbconnect;
// var fbAuth = require('./authentication.js');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var GoogleStrategy = require('passport-google-oauth2').Strategy;
var https = require('https');
var http = require('http');
var WebSocketServer = require('ws').Server;

app.use(cors());

/*
	var options = {
		key:    fs.readFileSync('ssl/server.key'),
		cert:   fs.readFileSync('ssl/server.crt'),
		ca:     fs.readFileSync('ssl/ca.crt')
	};	
*/



/*
var httpc = https.createServer(options, app);
var io = require('socket.io')(httpc);

app.get('/', function(req, res) {
  res.sendFile(__dirname + '/public/index.html');
});

io.on('connection', function(socket) {
  console.log('new connection');
  socket.emit('message', 'This is a message from the dark side.');
});

httpc.listen(443, function() {
  console.log('server up and running at 443 port');
});
*/
/*
var http = https.createServer(options);
io = require('socket.io').listen(http);     //socket.io server listens to https connections
http.listen(3003);
*/


var options = {
    key:    fs.readFileSync('/var/www/html/doctorssslcertificates/praecura.key'),
    cert:   fs.readFileSync('/var/www/html/doctorssslcertificates/praecura.crt')
};

var httpc = https.createServer(options);
// var httpc = http.createServer(apph);
var io = require('socket.io').listen(httpc);
httpc.listen(3000, function(){
	console.log('Listening the port:' + 3000);
});

io.sockets.on('connection',function(socket){
	console.log('Into the chat connection server..........');
	socket.on('message',function(data){
		console.log('recieved message from', data.from, '--data--', JSON.stringify(data.text));
		console.log(data);
	
		var chatdata = {discussion_id: data.discussion_id, user_id: data.from, user_message: data.text};
		var q = "INSERT into doc_chat_messages SET ?";
		dbconnection.query(q,chatdata,function(err,discussdata){
			if(err){
				var data=({status:0,message:err});
			}else{
				var data=({status:1,message:'Chatting'});
			}
			// res.send(data);
		});
	
		io.sockets.emit('broadcast',{
			payload: data.text,
			source: data.to,
			from:data.from
		// });
		});
	});
});



//
//
//// Emit welcome message on connection
//io.on('connection', function(socket) {
//    // Use socket to communicate with this particular client only, sending it it's own id
//    socket.emit('welcome', { message: 'Welcome!', id: socket.id });
//
//    socket.on('i am client', console.log);
//});

/*
	var httpc =require('https').createServer(app),
	io = require('socket.io').listen(httpc);
	//	var socket = io.connect('/chat/', {secure: true});
	http.listen(3003, function(){
		console.log('Listening the port:' + 3003);
	});

*/	
	
/*		
var freeice = require('freeice');
var quickconnect = require('rtc-quickconnect');
 
// initialise a configuration for one stun server 
var qcOpts = {
  room: 'icetest',
  iceServers: freeice()
};
 
// go ahead and connect 
quickconnect('https://wwww.praecura.com:3000', qcOpts)
  .createDataChannel('chat')
  .once('channel:opened:chat', function(peerId, dc) {
    console.log('data channel opened for peer id: ' + peerId);
 
    dc.onmessage = function(evt) {
      console.log('peer ' + peerId + ' says: ' + evt.data);
    };
 
    dc.send('hi');
  });

*/  

var yetify = require('yetify'),
    config = require('getconfig'),
    // fs = require('fs'),
    sockets = require('signal-master/sockets'),
    vport = 9000, // parseInt(process.env.PORT || config.server.port, 10),
    server_handler = function (req, res) {
        res.writeHead(404);
        res.end();
    },
    server = null;

// Create an http(s) server instance to that socket.io can listen to
if (config.server.secure) {
    server = require('https').Server({
        key: fs.readFileSync('/var/www/html/doctorssslcertificates/praecura.key'), // fs.readFileSync(config.server.key),
        cert: fs.readFileSync('/var/www/html/doctorssslcertificates/praecura.crt'), // fs.readFileSync(config.server.cert),
        passphrase: config.server.password
    }, server_handler);
} else {
    server = require('http').Server(server_handler);
}
server.listen(vport);

sockets(server, config);

if (config.uid) process.setuid(config.uid);

var httpUrl;
if (config.server.secure) {
    httpUrl = "https://localhost:" + vport;
} else {
    httpUrl = "http://localhost:" + vport;
}
console.log(yetify.logo() + ' -- signal master is running at: ' + httpUrl);	
	
/*	
var serverConfig = {
	key:    fs.readFileSync('/var/www/html/doctorssslcertificates/praecura.key'),
    cert:   fs.readFileSync('/var/www/html/doctorssslcertificates/praecura.crt')
};	
	
// Create a server for the client html page
var handleRequest = function(request, response) {
    // Render the single client html file for any request the HTTP server receives
    console.log('request received: ' + request.url);

    if(request.url == '/') {
        response.writeHead(200, {'Content-Type': 'text/html'});
        response.end(fs.readFileSync('client/index.html'));
    } else if(request.url == '/webrtc.js') {
        response.writeHead(200, {'Content-Type': 'application/javascript'});
        response.end(fs.readFileSync('client/webrtc.js'));
    }else{
		response.writeHead(200, {'Content-Type': 'application/javascript'});
        response.end(fs.readFileSync('client/webrtc.js'));
	}
};

var httpsServer = https.createServer(serverConfig, handleRequest);
httpsServer.listen(9000);

// ----------------------------------------------------------------------------------------

// Create a server for handling websocket calls
var wss = new WebSocketServer({server: httpsServer});

wss.on('connection', function(ws) {
    ws.on('message', function(message) {
        // Broadcast any received message to all clients
        console.log('received: %s', message);
        wss.broadcast(message);
    });
});

wss.broadcast = function(data) {
	console.log('Sending broadcast streaming.....');
    for(var i in this.clients) {
        this.clients[i].send(data);
    }
};

console.log('Server running. Visit https://localhost:9000 in Firefox/Chrome (note the HTTPS; there is no HTTP -> HTTPS redirect!)');	
*/	
	
/*	
//	Video chat
var ExpressPeerServer = require('peer').ExpressPeerServer;
var server = ExpressPeerServer({
  port: 9000,
  ssl: {
    key: fs.readFileSync('/var/www/html/doctorssslcertificates/praecura.key'),
    cert: fs.readFileSync('/var/www/html/doctorssslcertificates/praecura.crt')
  }
});

var options = {debug: true};

app.use('/peerjs', ExpressPeerServer(server, options));

server.on('connection', function(id) { 
	console.log('In the video connection');
});

server.on('disconnect', function(id) { 
	console.log('In the video disconnection');
});
*/


app.use(session({
  secret: 'doctorsite',
  resave: false,
  saveUninitialized: true
  // cookie: { secure: true }
}));

var api = require('./routes/api');
var adminapi = require('./routes/adminapi');
// GET /style.css etc
app.use(express.static(__dirname + '/public'));
//app.use(bodyParser.json()); // for parsing application/json
//app.use(bodyParser.urlencoded({ extended: true })); // for parsing application/x-www-form-urlencoded
app.use(bodyParser.json({limit:'50mb'}));
app.use(bodyParser.json({type: 'application/vnd.api+json'}));
app.use(bodyParser.urlencoded({ extended: true ,limit:'50mb'}));

//	app.use(expressSession({secret: 'mySecretKey'}));
app.use(passport.initialize());
app.use(passport.session());
app.use('/api',api);
app.use('/adminapi',adminapi);
require('./config/passport')(passport);

// serialize and deserialize
passport.serializeUser(function(user, done) {
  console.log('serializeUser: ' + user._id);
  done(null, user._id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user){
    console.log(user);
      if(!err) done(null, user);
      else done(err, null);
    });
});

// routes
/*
	app.get('/', routes.index);
	app.get('/ping', routes.ping);
	app.get('/account', ensureAuthenticated, function(req, res){
	  User.findById(req.session.passport.user, function(err, user) {
		if(err) {
		  console.log(err);  // handle errors
		} else {
		  res.render('account', { user: user});
		}
	  });
	});
*/

app.get('/auth/facebook',  passport.authenticate('facebook'), function(req, res){});
  
app.get('/auth/facebook/callback',
  passport.authenticate('facebook', { failureRedirect: '/' }),
  function(req, res) {
    res.redirect('/account');
  });

app.get('/auth/google',
  passport.authenticate('google', { scope: [
    'https://www.googleapis.com/auth/plus.login',
    'https://www.googleapis.com/auth/plus.profile.emails.read'
  ] }
));

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/' }),
  function(req, res) {
    res.redirect('/account');
  });
  
/*
passport.serializeUser(function(user, done) {
  done(null, user.username);
});

passport.deserializeUser(function(username, done) {
   new Model.User({username: username}).fetch().then(function(user) {
      done(null, user);
   });
});

passport.use(new LocalStrategy({
   usernameField: 'email',
   passwordField: 'password'
}, function(username, password, done){	
	dbconnection.query('SELECT * FROM doc_patient WHERE email ="'+username+'" AND password="'+password+'"', function(err,users){
		console.log('In the select');
		console.log(err);
		console.log(users);
	});
	console.log('In the passport use:'+username+":"+password+":"+done);
}));
*/

app.get('*', function(req, res) {
  res.redirect('/#' + req.originalUrl);
});


var port=1112;
app.listen(port,function(err){
	if(err){
		console.log("server error");
	}else{
		console.log("server is running on 52.36.81.32:"+port);
	}
});