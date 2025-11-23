const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { v4: uuid } = require('uuid');

// Since we can't use fs.readFileSync in Code Engine, you'll need to store these as environment variables
// Store the full PEM content in environment variables: CLIENT_PRIVATE_KEY and CLIENT_PUBLIC_KEY
// In Code Engine, set these as secrets or configmaps

// A time period of 45 days in milliseconds.
const TIME_45_DAYS = 1000 * 60 * 60 * 24 * 45;

/**
 * Generates a signed JWT with encrypted user payload
 */
function createJWTString(anonymousUserID, sessionInfo, context) {
  // Get keys from environment variables
  // DECODE THE BASE64-ENCODED KEYS
  const PRIVATE_KEY_B64 = process.env.CLIENT_PRIVATE_KEY_B64;
  const PUBLIC_KEY_B64 = process.env.SERVER_PUBLIC_KEY_B64;

  if (!PRIVATE_KEY_B64 || !PUBLIC_KEY_B64) {
    throw new Error('Missing CLIENT_PRIVATE_KEY_B64 or SERVER_PUBLIC_KEY_B64 environment variables');
  }

  const PRIVATE_KEY = Buffer.from(PRIVATE_KEY_B64, 'base64').toString('utf-8');
  const PUBLIC_KEY = Buffer.from(PUBLIC_KEY_B64, 'base64').toString('utf-8');

  // This is the content of the JWT
  const jwtContent = {
    // This is the subject of the JWT which will be the ID of the user
    sub: anonymousUserID,
    // This object is optional and contains any data you wish to include as part of the JWT
    user_payload: {
      custom_message: 'Welcome to the multiverse, Daniel',
      name: 'The System',
    },
    context
  };

  // If the user is authenticated, then add the user's real info to the JWT
  if (sessionInfo) {
    jwtContent.user_payload.name = sessionInfo.userName;
    jwtContent.user_payload.custom_user_id = sessionInfo.customUserID;
  }

  const dataString = JSON.stringify(jwtContent.user_payload);

  // Encrypt the data
  const encryptedBuffer = crypto.publicEncrypt(
    {
      key: PUBLIC_KEY,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'  // Specify OAEP padding with SHA256
    },
    Buffer.from(dataString, 'utf-8')
  );

  // Convert encrypted data to base64
  jwtContent.user_payload = encryptedBuffer.toString('base64');
  console.log('Encrypted payload:', jwtContent.user_payload);

  // Now sign the jwt content to make the actual jwt
  const jwtString = jwt.sign(jwtContent, PRIVATE_KEY, {
    algorithm: 'RS256',
    expiresIn: '45d', // FIX: Use a duration string that matches your constant
  });

  return jwtString;
}

/**
 * Gets or creates anonymous user ID
 */
function getOrCreateAnonymousID(existingId) {
  if (existingId) {
    return existingId;
  }
  // Create a new anonymous ID
  // FIX: .substr() is deprecated, use .slice()
  return `anon-${uuid().slice(0, 5)}`;
}

/**
 * Main function for IBM Code Engine
 * Handles requests to /createJWT?user_id=xxxxx
 */
function main(args) {
  try {
    // Log incoming args for debugging
    console.log('Incoming args:', JSON.stringify(args, null, 2));
    
    // Handle both query parameters and body parameters
    // In Code Engine, query parameters come through args.__ow_query or directly in args
    // The user_id from query parameter takes precedence
    let anonymousUserID = null;
    
    // Check for user_id in different possible locations
    if (args.user_id) {
      // Direct query parameter
      anonymousUserID = args.user_id;
    } else if (args.__ow_query) {
      // Parse from query string (e.g., "?user_id=123")
      // Check for '?' and remove it if present
      const queryString = args.__ow_query.startsWith('?') ? args.__ow_query.substring(1) : args.__ow_query;
      const params = new URLSearchParams(queryString);
      if (params.has('user_id')) {
        anonymousUserID = params.get('user_id');
      }
    } else if (args.anonymousUserId) {
      // Fallback to body parameter
      anonymousUserID = args.anonymousUserId;
    }
    
    // Generate anonymous ID if not provided or empty
    anonymousUserID = getOrCreateAnonymousID(anonymousUserID);
    
    // Session info can be passed in the request body
    const sessionInfo = args.sessionInfo || null;
    
    // Context can be customized or use defaults
    const context = args.context || {
      wxo_user_name: anonymousUserID,
      name: "Daniel Benner",
      rank: "noob",
      planet: "Earth"
    };

    // Generate the JWT
    const token = createJWTString(anonymousUserID, sessionInfo, context);

    // Return the response
    return {
      statusCode: 200,
      headers: { 
        'Content-Type': 'application/json',
        // Include cookie header if you want to set the anonymous ID cookie
        'Set-Cookie': `ANONYMOUS-USER-ID=${anonymousUserID}; Max-Age=${Math.floor(TIME_45_DAYS / 1000)}; HttpOnly; Path=/`
      },
      body: {
        token: token,
        anonymousUserId: anonymousUserID,
        message: 'JWT generated successfully'
      }
    };
  } catch (error) {
    console.error('Error generating JWT:', error);
    return {
      statusCode: 500,
      headers: { 
        'Content-Type': 'application/json'
      },
      body: {
        error: 'Failed to generate JWT',
        message: error.message
      }
    };
  }
}

module.exports.main = main;