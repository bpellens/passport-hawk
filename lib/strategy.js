/**
 * Module dependencies.
 */
var passport = require('passport')
	, util = require('util')
	, hawk = require('hawk');

var xtend = require('xtend');

/**
 * `Strategy` constructor.
 *
 * The HTTP Hawk authentication strategy authenticates requests based on
 * a bearer token contained in the `Authorization` header field or 
 * `hawk` query parameter.
 *
 * Applications must supply a `verify` callback which accepts an `id` and
 * then calls the `done` callback supplying a `credentials` object which 
 * should contains a `key` property matching the MAC, an `algorithm` 
 * property and a `user` property. 
 * If the user is not valid return false
 * `false` as the user.
 * 
 * Examples:
 *
 *     passport.use(new HawkStrategy(
 *       function(id, done) {
 *         User.findById({ _id: id }, function (err, user) {
 *           if (err) { return done(err); }
 *           if (!user) { return done(null, false); }
 *           return done(null, user);
 *         });
 *       }
 *     ));
 *
 * @param {Function} verify
 * @api public
 */
function HawkStrategy(bewit, verify) {
	if(typeof bewit == 'function'){
		verify = bewit;
		bewit = false;
	}
	if(typeof bewit == 'object'){
		bewit = bewit.bewit;
	}
	if (!verify) throw new Error('HTTP Hawk authentication strategy requires a verify function');
  
	this.name = 'hawk';
	this._verify = verify;
	this._bewit = bewit;
	passport.Strategy.call(this);
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(HawkStrategy, passport.Strategy);

/**
 * Authenticate request based on the contents of a HTTP Hawk authorization
 * header or query string parameter.
 *
 * @param {Object} req
 * @api protected
 */
HawkStrategy.prototype.authenticate = function(req) {
	//express change req.url when mounting with app.use
	//this creates a new request object with url = originalUrl
	req = xtend({}, req, { url: req.originalUrl || req.url });

	var options = {};
	
	// Set the payload in case of a POST or PUT in order to perform payload validation
	if (req.method === "POST" || req.method === "PUT") {
		options.payload = ((req.rawBody !== null && req.rawBody !== undefined) ? req.rawBody : '')
	}
	
	if (this._bewit){
		hawk.uri.authenticate(req, this._verify, options, function (err, credentials, ext) {
			if (err) {
				return this.error(err);
			}
			this.success(credentials.user, ext);
		}.bind(this));
	} else{
		hawk.server.authenticate(req, this._verify, options, function (err, credentials, ext) {
			if (err) {
				return this.error(err);
			}
			this.success(credentials.user, ext);
		}.bind(this));
	}
};

/**
 * Expose `Strategy`.
 */
module.exports = HawkStrategy;
