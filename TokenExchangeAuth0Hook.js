/* eslint-disable camelcase */
/* eslint-disable max-len */
/**
@param {object} client - information about the client
@param {string} client.name - name of client
@param {string} client.id - client id
@param {string} client.tenant - Auth0 tenant name
@param {object} client.metadata - client metadata
@param {array|undefined} scope - array of strings representing the scope claim or undefined
@param {string} audience - token's audience claim
@param {object} context - additional authorization context
@param {object} context.webtask - webtask context
@param {function} cb - function (error, accessTokenClaims)
*/
module.exports = function(client, scope, audience, context, cb) {
    const access_token = {};
    access_token.scope = scope; // do not remove this line
    
    if (context.body.subject_token_type && context.body.subject_token_type === 'urn:ietf:params:oauth:token-type:jwt' && context.body.subject_token) {
      doTokenExchange(cb);
    } else {
      // No subject_token to validate, read and exchange claims with
      // Completed Successfully, return access_token
      cb(null, access_token); // Return success
    }
  
    // FUNCTIONS ONLY FROM THIS POINT-------------------------------------------------------------------------------------------------------------
  
    /**
   * Get the JWKS signing key to validate the access_token sent in as subject_token
   * kid is defined in the header of the access_token
   * Platform Strategy - Oct 2020
   * @param {string} kid The private key to be matched
   * @param {string} jwksCallBack completed callback (error, key)
   */
    function getSigningKey(kid, jwksCallBack) {
      const jwks = require('jwks-rsa'); // jwks-rsa (1.10.1)
  
      const jwksClient = jwks({
        jwksUri: 'https://%%auth0domain%%/.well-known/jwks.json',
      });
  
      // Store the JWKS keys in persistant storage
      // Webtask loses memory space in 30 seconds
      context.webtask.storage.get(
          function(error, data) {
            if (error) {
              jwksCallBack('Webtask.Storage.Get: ' + error.toString(), null);
            } else if (data && (!data.timestamp || !data.keys)) { // Bad data
              jwksCallBack('Bad data in context.webtask.storage', null);
            } else if (!data || ((Date.now() - data.timestamp) > 600000)) { // No data or 10 minute expiration
              console.log('JWKS Signing Key cache miss');
  
              jwksClient.getSigningKeys(function(jwksError, keys) {
                if (jwksError) {
                  jwksCallBack('JWKS getSingingKeys: ' + jwksError, null);
                } else {
                  // Add the key to the storage as a cache
                  context.webtask.storage.set({timestamp: Date.now(), keys: keys}, {force: 1}, function(storageError) {
                    if (storageError) {
                      jwksCallBack('Webtask.Storage.Set: ' + storageError);
                    } else {
                      getKeyForKid(kid, keys, jwksCallBack); // Done - got the JWKS keys and added them to the cache. Find key for kid
                    }
                  });
                }
              });
            } else {
              console.log('JWKS Signing Key cache hit');
              getKeyForKid(kid, data.keys, jwksCallBack);
            }
          });
    } // function getSigningKey
  
  
    /**
   *  Find the jwks key by kid
   * Platform Strategy - Oct 2020
   * @param {string} kid The private key to be matched
   * @param {[keys]} keys The array of key object from jwks
   * @param {string} jwksCallBack completed callback (error, key)
   */
    function getKeyForKid(kid, keys, jwksCallBack) {
      let hit = false;
  
      keys.forEach(function(key) {
        if (!hit && key.kid === kid) {
          hit = true; // the loop keeps running, make sure it doesn't do anything
          jwksCallBack(null, key);
        }
      });
  
      if (!hit) {
        jwksCallBack('Kid [' + kid + '] not found in JWKS keys', null);
      }
    } // function getKeyForKid
  
    /**
   *  When a subject_token is provide exchange token claims
   * Platform Strategy - Oct 2020
   * @param {function} exchangeCb completed callback (error, access_token)
   */
    function doTokenExchange(exchangeCb) {
      // Token Exchange
      // Transfer aud and sub if present in provided subject_token
      // Allows the original subject to pass thru
      // NPM Modules Required: jsonwebtoken (8.5.1), jwks-rsa (1.10.1)
  
      const jwt = require('jsonwebtoken'); // jsonwebtoken (8.5.1)
  
      // Verify the token
      // First jwksClient gets the public key from the public jwks url
      // this is async so we use callbacks and provide a function to get the public key by kid
      // The second function receives the decoded token, transfers the claims (if any) and returns
  
      jwt.verify(context.body.subject_token,
          function(header, callback) {
          // Access Token Header decoded. Get the matching key from Identity Provider
  
            // Get the public key for the token header's kid from Auth0 Domain's JWKS public endpoint
            getSigningKey(header.kid, function(err, key) {
              if (err) {
              // Error: Unable to retrieve public key from JWKS needed to verify the signature of the token
              // Log and return failure
                console.log(err);
                exchangeCb(err); // Return failure
              } else {
              // Success
              // Return to jwt.verify the public key that corresponds the kid in the token header
                const signingKey = key.publicKey || key.rsaPublicKey;
                callback(null, signingKey);
              }
            });
          },
          {ignoreExpiration: false}, // options - expired tokens will NOT be accepted (default behavior but making that clear)
          // Function is called after the token is decoded and the token's signature is verified
          function(err, decoded) {
            if (err) {
            // Error - unable to decod the token
            // Log and return failure
              console.log(err);
              exchangeCb(err); // Return failure
            } else {
              //-------------------------------------------------------------------------------
              // At this point we've validated the subject_token is a valid access token for the domain - signature and all
              // If reusing this code this is the block to tweak
              
              if(decoded && decoded.permissions){
                access_token["http://exchange/"] = {};
                access_token["http://exchange/"].sub = decoded.sub;
                access_token["http://exchange/"].permissions = decoded.permissions;
              }
  
              
              // Completed Successfully, return the access token
              exchangeCb(null, access_token); // Return success
            }
          });
    } // function doTokenExchange
  };
  