const router = require("express")
const { LogLevel } = require('@azure/msal-node');
require('dotenv').config();
const verifyad = require("./verifyad");

const authConfig = {
  auth: {
    clientId: process.env.CLIENT_ID,
    authority: 'https://login.microsoftonline.com/'+process.env.TENANT_ID,
    clientSecret: process.env.CLIENT_SECRET,
  },
  system: {
    loggerOptions: {
      loggerCallback: function (loglevel, message, containsPii) {
        console.log(message);
      },
      piiLoggingEnabled: false,
      logLevel: LogLevel.Verbose,
    },
  },
};

const msal = require('@azure/msal-node');
const pca = new msal.ConfidentialClientApplication(authConfig);
const authRoute = router.Router()

/** Get oAuth token */
authRoute.get('/.auth/login/aad/callback', async (req, res) => {
  try {
    console.log("Callback called");
    const tokenRequest = {
      code: req.query.code,
      redirectUri: 'http://localhost:3001/.auth/login/aad/callback', // This should be the callback url set in the Azure Intra AD
      scopes: ['user.read'],
    };
    console.log("request",tokenRequest);
    const response = await pca.acquireTokenByCode(tokenRequest);
    console.log(response);
    // Verification of the token
    (0, verifyad.default)(response.idToken);

    const userName = response.idTokenClaims.preferred_username.split('@');
    const userId = userName[0];

    // Your additional logic here

    // Store the cookies
    res.cookie('accessToken', response.accessToken, {
      path: '/',
      secure: true,
    });
    res.cookie('idToken', response.idToken, {
      path: '/',
      secure: true,
    });
    res.cookie('uid', response.idTokenClaims.preferred_username, {
      path: '/',
      secure: true,
    });
    res.cookie('userName', response.idTokenClaims.name, {
      path: '/',
      secure: true,
    });

    res.redirect('/');
  } catch (error) {
    console.error(error);
    res.status(500).send(error);
  }
});

module.exports = authRoute;
