//Define the local strategy
var LocalStrategy = require('passport-local').Strategy;

//Import the user model
var User = require('../models/user'); //Class 'User' - need to create an instance

//Pass in reference to passport from app.js
module.exports = function(passport){
	//Serialize user (pass info to sessionStore)
	passport.serializeUser(function(user, done){
		done(null, user);
	});
	//Deserialize user (take info from sessionStore)
	passport.deserializeUser(function(id, done){
		User.findById(id, function(err, user){
			done(err, user);
		});
	});
	
	passport.use('local-login', new LocalStrategy({
		passReqToCallback:true 
	}, 
	function(req, username, password, done){
		//Asynchronous process
		process.nextTick(function() {
			User.findOne({
				'username': username
			}), function(err, user) {
				if(err){
					return done(err);
				}
				//If no valid username, error
				if(!user){
					return done(null, false, req.flash('loginMessage','Incorrect Username'));
				}
				//If no valid password, error
				if(!user.validPassword(password)){
					return done(null, false, req.flash('loginMessage', 'Incorrect Password'));
				}
				//Everything is ok, proceed with login
				return done(null, user);
			}
		});
	}));
	
	//Configure registration for local strategy
	passport.use('local-registration', new LocalStrategy({
		passReqToCallback: true
	},
		function(req, username, password, done) {
			//Asynchronous process
			process.nextTick(function(){
				//If user is not already logged in
				if(!req.user) {
					User.findOne({'username': username},
					//If errors
					function(err, user){
						if(err){
							return done(err);
						}
						//Check username to see if it's taken
						if(user) {
							return done(null, false, req.flash('registerMessage', 'Username already taken.'));
						}
						else {
							//Create the user
							var newUser = new User(req.body); //Grabs the "posted" info from registration
							newUser.password = newUser.generateHash(newUser.password); //Hash the password
							newUser.provider = 'local';
							newUser.created = Date.now();
							newUser.updated = Date.now();
							newUser.save(function(err){
								if(err) {
									throw err;
								}
								return done(null, newUser);
							});
						}
					});
				} else {
					//Everything is okay - user is registered
					return done(null, req.user);
				}
			});
		}));
}