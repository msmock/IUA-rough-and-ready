const express = require('express')
const url = require('url')
const bodyParser = require('body-parser')
const randomstring = require('randomstring')
const querystring = require('querystring')
const cons = require('consolidate')
const __ = require('underscore')
__.string = require('underscore.string')
const jose = require('jsrsasign')
const session = require('express-session')
const axios = require('axios')

const mongo = require('mongodb-memory-server')
var mongoClient = require('mongodb').MongoClient

const app = express()

//
const mongoOptions = {
  instance: {
    port: 27017,
    dbName: 'OIDC_Test'
  }
}

let mongoServer = new mongo.MongoMemoryServer(mongoOptions)

async function initMongoDB() {
  console.log('Start mongo db on port %s', mongoOptions.instance.port)
  mongoServer.start()
}

initMongoDB();

// use mongodb as sesion store
const MongoDBStore = require('connect-mongodb-session')(session);

var store = new MongoDBStore({

    uri: 'mongodb://localhost:27017/connect_mongodb_session_test?connectTimeoutMS=10',
    databaseName: 'OIDC_Test'

  },
  function(error) {
    // if (error) console.log('Init Error: %s', error)
  })

store.on('error', function(error) {
  console.log('State Error: %s', error);
})

// session handling
app.use(session({
  secret: randomstring.generate(10),
  name: 'oidc_session_cookie',
  saveUninitialized: true,
  cookie: {
    maxAge: 5 * 60 * 1000 // 5 minutes
  },
  store: store,
  resave: true,
  saveUninitialized: true
}))

app.use(bodyParser.json())
app.use(bodyParser.urlencoded({
  extended: true
}))

app.engine('html', cons.underscore)
app.set('view engine', 'html')
app.set('views', 'files/oidcProvider')
app.set('json spaces', 1)

// authorization server information
const oidcServer = {
  issuer: 'http://localhost:9003/',
  authenticationURL: 'http://localhost:9003/oidc_authenticate',
  authorizationURL: 'http://localhost:9003/oidc_authorize',
  tokenURL: 'http://localhost:9003/oidc_token',
  logoutURL: 'http://localhost:9003/oidc_logout',
  userinfoEndpoint: 'http://localhost:9003/oidc_userinfo'
}

// client information esp. the allowed scopes
const clients = [{
  clientId: 'oidc-client-1',
  clientSecret: 'oidc-client-secret-1',
  redirectUris: ['http://localhost:9001/oidc_callback'],
  logoutURL: 'http://localhost:9001/oidc_logout',
  scope: 'openid profile email phone address',
  description: 'The IUA Server'
}, {
  clientId: 'oidc-client-2',
  clientSecret: 'oidc-client-secret-2',
  redirectUris: ['http://localhost:9000/oidc_callback'],
  logoutURL: 'http://localhost:9000/oidc_logout',
  scope: 'openid profile email phone address',
  description: 'My client application'
}]

// the registered users
const userInfo = {

  alice: {
    sub: '9XE3-JI34-00132A',
    name: 'Alice Lewis',
    gender: 'female',
    birthdate: '1990-06-14',
    email: 'alice.wonderland@example.com',
    email_verified: true,
    address: {
      country: 'GB'
    }
  },

  bob: {
    sub: '1ZT5-OE63-57383B',
    name: 'Bob James',
    gender: 'male',
    birthdate: '1990-06-14',
    email: 'bob.loblob@example.net',
    email_verified: false,
    address: {
      country: 'USA'
    }
  }
}

// used for oidc sessions which cross http sessions
const oidcCache = {}

const getClient = function(clientId) {
  return __.find(clients, function(client) {
    return client.clientId === clientId
  })
}

const getUser = function(name) {
  return __.find(userInfo, function(user, key) {
    return key === name
  })
}

const findUserBySub = function(sub) {
  return __.find(userInfo, function(user, key) {
    return user.sub === sub
  })
}

// deserialize the JWS token and return the payload
var getJWSPayload = function(token) {
  return token ? jose.jws.JWS.parse(token).payloadObj : null
}

/**
 * serves the server metadata
 **/
app.get('/', function(req, res) {
  res.render('index', {
    clients: clients,
    authServer: oidcServer
  })
})

/**
 * serves the login form
 **/
app.get('/oidc_authenticate', function(req, res) {

  console.log('/oidc_authenticate ...')

  console.log('Request query is:')
  console.log(req.query)

  // check if we have an open session. Delegate to /oidc_authorize if true.
  console.log('Current session is: ')
  console.log(req.session)

  // open login form, if we don't have a running session
  if (!req.session.query || !req.session.query.user) {
    req.session.query = req.query
    res.render('authenticate')
    console.log('/oidc_authenticate done')
    return
  }

  console.log('We already have a http session with authenticated user:')
  console.log(req.session)

  // No scope granted to the user session
  if (!req.session.query.scope_granted || req.session.query.scope_granted === 'NONE') {
    res.render('approve', {
      client: getClient(req.query.client_id),
      scope: req.query.scope.split(' '),
      authQuery: req.session.query
    })
    console.log('/oidc_authenticate done')
    return
  }

  // generate authorization code and store to session
  req.session.code = randomstring.generate(10)

  // set the query data
  req.query.user = req.session.query.user
  req.query.scope_granted = req.session.query.scope_granted
  oidcCache[req.session.code] = req.query

  console.log('Create a new oidc session for the new single sign-on request:')
  console.log('Authorization code is: %s', req.session.code)
  console.log('Session for the client using single sign on is:')
  console.log(oidcCache[req.session.code])

  // update state and code_challenge stored on session with the one from the current request
  req.session.query.state = req.query.state
  req.session.query.code_challenge = req.query.code_challenge

  // redirect to the client
  let urlParsed = url.parse(req.query.redirect_uri)
  delete urlParsed.search // this is a weird behavior of the URL library

  urlParsed.query = urlParsed.query || {}
  urlParsed.query.code = req.session.code
  urlParsed.query.state = req.session.query.state

  console.log('redirect to %s', url.format(urlParsed))
  res.redirect(url.format(urlParsed))

  console.log('/oidc_authenticate done')
  return
})

/**
 * authorize access to identity provider data
 **/
app.post('/oidc_authorize', function(req, res) {

  console.log('/oidc_authorize ...')

  let username = req.body.username
  let password = req.body.password

  console.log('session query is:')
  console.log(req.session.query)

  console.log('authenticate user: %s with password: %s', username, password)

  // verify credentials
  let user = getUser(username.trim())
  req.session.query.user = user

  if (!user) {
    console.log("Error: Unknown user " + username)
    res.render('error', {
      error: 'Invalid credentials'
    })
    console.log('/oidc_authorize done')
    return
  }

  let client = getClient(req.session.query.client_id)

  if (!client) {

    console.log('Unknown client %s', req.session.query.client_id)
    res.render('error', {
      error: 'Unknown client'
    })
    console.log('/oidc_authorize done')
    return

  } else if (!__.contains(client.redirectUris, req.session.query.redirect_uri)) {

    console.log('Mismatched redirect URI, expected %s got %s', client.redirectUris, req.session.query.redirect_uri)
    res.render('error', {
      error: 'Invalid redirect URI'
    })
    console.log('/oidc_authorize done')
    return

  } else {

    let requestedScope = req.session.query.scope ? req.session.query.scope.split(' ') : undefined
    let declaredScope = client.scope ? client.scope.split(' ') : undefined

    if (__.difference(requestedScope, declaredScope).length > 0) {
      // client asked for a scope it couldn't have
      let urlParsed = url.parse(req.session.query.redirect_uri)
      delete urlParsed.search // this is a weird behavior of the URL library
      urlParsed.query = urlParsed.query || {}
      urlParsed.query.error = 'invalid_scope'
      res.redirect(url.format(urlParsed))
      return
    }

    /**
     * show page to resource owner to authorize the access.
     **/
    res.render('approve', {
      client: client,
      scope: requestedScope,
      authQuery: req.session.query
    })

    console.log('/oidc_authorize done')
    return
  }

  return
})

/**
 * called by the user agent to present the UI to authorize client application
 * access to selected scopes
 **/
app.post('/oidc_approve', function(req, res) {

  console.log('/oidc_approve ...')
  console.log('present UI to resource owner to authorize client access.')

  let query = req.session.query

  if (!query) {
    res.render('error', {
      error: 'Do authorization request first!'
    })
    console.log('/oidc_approve done.')
    return
  }

  console.log('Request body is:')
  console.log(req.body)

  // resource owner denied access
  if (!req.body.approve) {

    let urlParsed = url.parse(query.redirect_uri)
    delete urlParsed.search // this is a weird behavior of the URL library

    urlParsed.query = urlParsed.query || {}
    urlParsed.query.error = 'Access denied.'

    res.redirect(url.format(urlParsed))
    console.log('/oidc_approve done.')
    return
  }

  // we got a response type we don't understand
  if (!(query.response_type === 'code')) {
    let urlParsed = url.parse(query.redirect_uri)
    delete urlParsed.search // this is a weird behavior of the URL library
    urlParsed.query = urlParsed.query || {}
    urlParsed.query.error = 'Unsupported response type'
    res.redirect(url.format(urlParsed))
    console.log('/oidc_approve done.')
    return
  }

  // get scope granted by resource owner
  let scope = __.filter(__.keys(req.body), function(s) {
      return __.string.startsWith(s, 'scope_')
    })
    .map(function(s) {
      return s.slice('scope_'.length)
    })

  let client = getClient(query.client_id)
  let declaredScope = client.scope ? client.scope.split(' ') : undefined

  // client asked for a scope not declared in registration
  if (__.difference(scope, declaredScope).length > 0) {
    let urlParsed = url.parse(query.redirect_uri)
    delete urlParsed.search // this is a weird behavior of the URL library
    urlParsed.query = urlParsed.query || {}
    urlParsed.query.error = 'Client asked for a scope not declared in registration'
    res.redirect(url.format(urlParsed))
    console.log('/oidc_approve done.')
    return
  }

  // generate authorization code and store to session
  req.session.code = randomstring.generate(10)
  oidcCache[req.session.code] = req.session.query

  console.log('Scope granted by owner is ' + scope)
  req.session.query.scope_granted = scope.join(' ')

  // redirect to the client
  let urlParsed = url.parse(req.session.query.redirect_uri)
  delete urlParsed.search // this is a weird behavior of the URL library

  urlParsed.query = urlParsed.query || {}
  urlParsed.query.code = req.session.code
  urlParsed.query.state = req.session.query.state

  res.redirect(url.format(urlParsed))

  console.log('/oidc_approve done.')
  return
})

// JWS signature
const sign = function(jwsPayload) {

  const header = {
    'typ': 'JWT',
    'alg': 'RS256',
    'kid': 'authserver'
  }

  // add a JWS signature to id_token
  const rsaKey = {
    'alg': 'RS256',
    'd': 'ZXFizvaQ0RzWRbMExStaS_-yVnjtSQ9YslYQF1kkuIoTwFuiEQ2OywBfuyXhTvVQxIiJqPNnUyZR6kXAhyj__wS_Px1EH8zv7BHVt1N5TjJGlubt1dhAFCZQmgz0D-PfmATdf6KLL4HIijGrE8iYOPYIPF_FL8ddaxx5rsziRRnkRMX_fIHxuSQVCe401hSS3QBZOgwVdWEb1JuODT7KUk7xPpMTw5RYCeUoCYTRQ_KO8_NQMURi3GLvbgQGQgk7fmDcug3MwutmWbpe58GoSCkmExUS0U-KEkHtFiC8L6fN2jXh1whPeRCa9eoIK8nsIY05gnLKxXTn5-aPQzSy6Q',
    'e': 'AQAB',
    'n': 'p8eP5gL1H_H9UNzCuQS-vNRVz3NWxZTHYk1tG9VpkfFjWNKG3MFTNZJ1l5g_COMm2_2i_YhQNH8MJ_nQ4exKMXrWJB4tyVZohovUxfw-eLgu1XQ8oYcVYW8ym6Um-BkqwwWL6CXZ70X81YyIMrnsGTyTV6M8gBPun8g2L8KbDbXR1lDfOOWiZ2ss1CRLrmNM-GRp3Gj-ECG7_3Nx9n_s5to2ZtwJ1GS1maGjrSZ9GRAYLrHhndrL_8ie_9DS2T-ML7QNQtNkg2RvLv4f0dpjRYI23djxVtAylYK4oiT_uEMgSkc4dxwKwGuBxSO0g9JOobgfy0--FUHHYtRi0dOFZw',
    'kty': 'RSA',
    'kid': 'authserver'
  }

  let privateKey = jose.KEYUTIL.getKey(rsaKey)
  return jose.jws.JWS.sign('RS256', JSON.stringify(header), jwsPayload, privateKey)
}

/**
 * generate the JWT access token
 **/
const generateTokens = function(clientId, userId, scope) {

  const idTokenPayload = {
    iss: 'http://localhost:9003/',
    sub: userId,
    aud: clientId,
    jti: randomstring.generate(10),
    scope: scope,
    exp: Math.floor(Date.now() / 1000) + (5 * 60),
    iat: Math.floor(Date.now() / 1000)
  }

  console.log('oidc id token payload is:')
  console.log(idTokenPayload)

  const payloadAsString = JSON.stringify(idTokenPayload)
  const idToken = sign(payloadAsString)

  const access_token = randomstring.generate(10)

  // store token to mongo db
  mongoClient.connect('mongodb://127.0.0.1:27017/', function(err, db) {

    if (err)
      throw err

    let dbo = db.db(mongoOptions.instance.dbName)

    dbo.collection('tokens').insertOne({
        subject: userId,
        client_id: clientId,
        access_token: access_token,
        id_token: idTokenPayload
      },
      function(err, result) {
        if (err)
          throw err
        console.log(result)
        db.close()
      })
  })

  console.log('Issuing access token: %s', access_token)
  console.log('and scope: %s', scope)

  const token_response = {
    access_token: access_token,
    token_type: 'Bearer',
    scope: scope,
    id_token: idToken
  }

  return token_response
}

/**
 * generate the JWT logout token
 **/
const generateLogoutToken = function(clientId, userId) {

  const token = {
    iss: 'http://localhost:9003/',
    sub: userId,
    aud: clientId,
    iat: Math.floor(Date.now() / 1000),
    jti: randomstring.generate(10),
    events: {
      'http://schemas.openid.net/event/backchannel-logout': {}
    }
  }
  return token
}

/**
 * called by the authorization client via backchannel.
 **/
app.post('/oidc_token', function(req, res) {

  console.log('/oidc_token ...')
  console.log('session is: ' + req.session.id)

  let clientId = null
  let clientSecret = null

  // check if the client uses http basic authorization
  let auth = req.headers['authorization']

  if (!auth) {
    console.log('Error: Authorization header missing.')
    res.status(401).json({
      error: 'Authorization header missing'
    })
    console.log('/oidc_token done.')
    return
  }

  const clientCredentials = Buffer.from(auth.slice('basic '.length), 'base64').toString().split(':')
  clientId = querystring.unescape(clientCredentials[0])
  clientSecret = querystring.unescape(clientCredentials[1])

  const client = getClient(clientId)

  // check if the client is known
  if (!client) {
    console.log('Error: Unknown client %s', clientId)
    res.status(401).json({
      error: 'Unknown client'
    })
    console.log('/oidc_token done.')
    return
  }

  // authenticate client
  if (client.clientSecret != clientSecret) {
    console.log('Mismatched client secret, expected %s got %s', client.clientSecret, clientSecret)
    res.status(401).json({
      error: 'Mismatched client secret'
    })
    console.log('/oidc_token done.')
    return
  }

  // verify grant type
  if (!(req.body.grant_type === 'authorization_code')) {
    console.log('Unsupported grant type %s', req.body.grant_type)
    res.status(400).json({
      error: 'Unsupported grant type '
    })
    console.log('/oidc_token done.')
  }

  // check if we have an open session for the autorization code
  let sessionData = oidcCache[req.body.code]

  console.log('OIDC session data are:')
  console.log(sessionData)

  if (!sessionData) {
    console.log('Error: Unknown authorization code, %s', req.body.code)
    res.status(400).json({
      error: 'Unknown authorization code'
    })
    console.log('/oidc_token done.')
    return
  }

  // remove the session
  delete oidcCache[req.body.code]

  // check if the session is assigned to the same client
  if (!(sessionData.client_id === clientId)) {
    console.log('No registered session for this client id. Expected %s got %s', sessionData.client_id, clientId)
    res.status(400).json({
      error: 'No registered session for this client id.'
    })
    console.log('/oidc_token done.')
    return
  }

  // verify the code challenge stored in session matches the code verifier
  if (sessionData.code_challenge != req.body.code_verifier) {
    console.log('Error: Invalid code verifier. Expected %s, got %s', sessionData.code_challenge, req.body.code_verifier)
    res.status(400).json({
      error: 'Invalid code verifier'
    })
    console.log('/oidc_token done.')
    return
  }

  // no error, thus
  const tokenResponse = generateTokens(clientId, sessionData.user.sub, sessionData.scope_granted)
  res.status(200).json(tokenResponse)
  console.log('Issued access token for authorization code: %s', req.body.code)
  console.log('/oidc_token done.')
  return
})

/**
 * The OpenID Connect user info endpoint
 **/
app.post('/oidc_userinfo', function(req, res) {

  console.log('/oidc_userinfo ...')

  // check the auth header first
  let auth = req.headers['authorization']
  let inToken = auth.slice('bearer '.length)

  if (!inToken) {
    console.log('Error: Missing access token.')
    res.status(400).json({
      error: 'Missing access token.'
    })
    console.log('/oidc_userinfo done.')
    return
  }

  // find the token in mongo db
  mongoClient.connect('mongodb://127.0.0.1:27017/', function(err, db) {

    if (err) {
      throw err
    }

    let dbo = db.db(mongoOptions.instance.dbName)

    dbo.collection('tokens').findOne({

      "access_token": inToken

    }, function(err, token) {

      if (err) {
        console.log('Error: No matching token found.')
        res.status(400).json({
          error: 'Unauthorized access. No matching token found in store.'
        })
        console.log('/oidc_userinfo done.')
        db.close()
        return
      }

      console.log('We found a matching token:')
      console.log(token)

      // TODO check token lifetime

      var user = findUserBySub(token.subject)
      if (!user) {
        console.log('Error: No user assigned to matching token.')
        res.status(400).json({
          error: 'Unauthorized access. No user assigned to matching token.'
        })
        console.log('/oidc_userinfo done.')
        return
      }

      console.log('We found a matching user:')
      console.log(user)

      res.status(200).json(user)
      console.log('/oidc_userinfo done.')

      db.close()
      return
    })
  })
})

// perform the required actions to logout
async function logout(subject) {

  console.log('logout ...')

  let resolveTokens = new Promise(function(resolve, reject) {

    // query all token of the user
    mongoClient.connect('mongodb://127.0.0.1:27017/', function(err, db) {
      if (err) {
        throw err;
      }
      // query the token assigned to this user
      let dbo = db.db(mongoOptions.instance.dbName)
      dbo.collection('tokens').find({
        "subject": subject
      }).toArray(function(err, tokens) {
        if (err) {
          throw err;
        }
        resolve(tokens)
        db.close()
      })
    })
  }) // end promise

  // snyc run the promise
  let tokens = await resolveTokens

  let propagate = function(token) {

    return new Promise(function(resolve, reject) {

      // TODO put to promize and use promiseAll
      let logoutClientId = token.client_id
      let logoutClient = getClient(logoutClientId)

      // call clients to logout
      axios.defaults.headers.post['Content-Type'] = 'application/x-www-form-urlencoded'
      axios.post(logoutClient.logoutURL, {
          logout_token: generateLogoutToken(logoutClientId, subject)
        }).then(function(response) {
          console.log('Backchannel logout request send to client %s.', logoutClientId)
          resolve ('OK')
        })
        .catch(function(error) {
          console.log('Error: Could not send logout to client %s (%s).', logoutClientId, logoutClient.description)
          resolve ('Failed')
        })
    })
  }

  // iterate the token found and call logout on the client
  let receivers = []
  tokens.forEach((token, i) => {
    receivers.push(propagate(token))
  }) // end iterating the tokens

  // asnc call all relying parties
  Promise.all(receivers)

  // delete the assigned sessions
  let destroySessions = new Promise(function(resolve, reject) {

    // query all token of the user
    mongoClient.connect('mongodb://127.0.0.1:27017/', function(err, db) {

      if (err) {
        throw err;
      }
      // query the token assigned to this user
      let dbo = db.db(mongoOptions.instance.dbName)

      dbo.collection('sessions').deleteMany({
        "session.query.user.sub": subject
      }, function(err) {
        if (err) {
          throw err;
        }
        resolve('OK')
        db.close()
      })
    })
  }) // end promise

  // sync execution of query
  await destroySessions

  console.log('logout done')
}

/**
 * The OpenID Connect logout
 **/
app.get('/oidc_logout', function(req, res) {

  console.log('/oidc_logout ...')

  console.log('Query is:')
  console.log(req.query)

  let inToken = req.query.id_token_hint

  if (!inToken) {
    console.log('Error: Missing id token hint.')
    res.status(400).json({
      error: 'Missing id token hint.'
    })
    console.log('/oidc_logout done.')
    return
  }

  let jwsPayload = getJWSPayload(inToken)
  let subject = jwsPayload.sub
  let clientId = jwsPayload.client_id

  logout(subject)

  res.render('info', {
    text: 'You are logged out.'
  })

  console.log('/oidc_logout done.')
  return
})


app.use('/', express.static('files/oidcProvider'))

const server = app.listen(9003, 'localhost', function() {
  const host = server.address().address
  const port = server.address().port
  console.log('OpenID Connect Server is listening at http://%s:%s', host, port)
})
