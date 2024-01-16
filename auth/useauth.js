"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getAppCookies = exports.getUserIdFromCookie = void 0;
require('dotenv').config(); 
var verifyad_1 = require("./verifyad.js");
var msal = require('@azure/msal-node');
var authConfig = {
  auth: {
    clientId: process.env.CLIENT_ID,
    authority: 'https://login.microsoftonline.com/'+process.env.TENANT_ID,
    clientSecret: process.env.CLIENT_SECRET
  },
  system: {
    loggerOptions: {
      loggerCallback: function (loglevel, message, containsPii) {
        // logMessage(LogLevel.INFO, message);
      },
      piiLoggingEnabled: false,
    },
  },
};


var config = {
  cookieNames: { idToken: 'idToken', uid: 'uid' },
  auth:{tokenURL: process.env.REDIRECT_URI}
};

var pca = new msal.ConfidentialClientApplication(authConfig);

/**
 * Returns OAuth toekn
 */
var getTokenFromCookie = function (req) {
  var parsedCookies = (0, exports.getAppCookies)(req);
  return parsedCookies && parsedCookies[config.cookieNames.idToken];
};
/**
 * Returns user id from cookie
 */
var getUserIdFromCookie = function (req) {
  var parsedCookies = (0, exports.getAppCookies)(req);
  var userId = '';
  userId = parsedCookies && parsedCookies[config.cookieNames.uid];
  userId = userId && decodeURIComponent(userId);
  if (userId.indexOf('@') !== -1) {
    userId = userId.split('@')[0];
  }

  return userId;
};
exports.getUserIdFromCookie = getUserIdFromCookie;

var getAppCookies = function (req) {
  var cookieStr = req.headers.cookie;
  var rawCookies = cookieStr && cookieStr.split('; ');
  // rawCookies = ['myapp=secretcookie, 'analytics_cookie=beacon;']
  var parsedCookies = {};
  rawCookies &&
    rawCookies.forEach(function (rawCookie) {
      var parsedCookie = rawCookie.split('=');
      // parsedCookie = ['myapp', 'secretcookie'], ['analytics_cookie', 'beacon']
      parsedCookies[parsedCookie[0]] = parsedCookie[1];
    });
  return parsedCookies;
};
exports.getAppCookies = getAppCookies;
/**
 * Middleware to check if a user is autenticated.
 */
var isUserAuthenticated = function (req, res, next) {
  console.log("inside user auth");
  if (req.path.includes('health-check') ||
    req.path.includes('getToken') ||
    req.path.includes('un-authorized') ||
    req.path.includes('.js') ||
    req.path.includes('.woff2') ||
    req.path.includes('.svg') ||
    req.path.includes('.png') ||
    req.path.includes('.css') ||
    req.path.includes('health-check') ||
    req.path.includes('.ico')) {
    return next();
  }
  else {
    // console.log("request from userAuth", req);
    var token = getTokenFromCookie(req);
    if (!token || !(0, verifyad_1.default)(token)) {

      var authCodeUrlParameters = {
        scopes: ['user.read'],
        redirectUri:config.auth.tokenURL
      };
      // get url to sign user in and consent to scopes needed for application
      pca
        .getAuthCodeUrl(authCodeUrlParameters)
        .then(function (response) {
          console.log("response from token", response);
          // redirecting the response
          res.redirect(response);
        })
        .catch(function (error) {
          console.log("Token url not called",error)
          return 0;
        });
    }
    else {
      return next();
    }
  }
};
module.exports = {
  isUserAuthenticated: isUserAuthenticated,
  getUserIdFromCookie: getUserIdFromCookie
};
