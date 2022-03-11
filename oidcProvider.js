const express = require('express')
const url = require('url')
const bodyParser = require('body-parser')
const randomstring = require('randomstring')
const querystring = require('querystring')
const cons = require('consolidate')
const __ = require('underscore')
__.string = require('underscore.string')
const session = require('express-session')
const axios = require('axios')

const mongo = require('mongodb-memory-server')
const mongoClient = require('mongodb').MongoClient

const jose = require('node-jose')
const fs = require('fs')

const app = express()

// load the private key for signing
const privateKey = fs.readFileSync('./keys/oidc/private-key.pem')
const publicKey = fs.readFileSync('./keys/oidc/public-key.pem')

// initialize mongodb
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

// called by the authorization client via backchannel.
app.post('/oidc_token', async (req, res) => {

  console.log('/oidc_token ...')
  console.log('session is: ' + req.session.id)

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

  let clientId = querystring.unescape(clientCredentials[0])
  let clientSecret = querystring.unescape(clientCredentials[1])

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

  // no error, thus build the token response
  const userId = sessionData.user.sub
  const scopeGranted = sessionData.scope_granted

  const idTokenPayload = {
    iss: 'http://localhost:9003/',
    sub: userId,
    aud: clientId,
    jti: randomstring.generate(10),
    scope: scopeGranted,
    exp: Math.floor(Date.now() / 1000) + (5 * 60),
    iat: Math.floor(Date.now() / 1000)
  }

  console.log('oidc id token payload is:')
  console.log(idTokenPayload)

  // JWS signature
  const jwsPayload = JSON.stringify(idTokenPayload)

  // read private key and sign. This creates the header as well
  let key = await jose.JWK.asKey(privateKey, "pem")

  // format: flattened or compact
  let format = {
    format: 'compact'
  }

  let idToken = await jose.JWS.createSign(format, key).update(jwsPayload).final()

  console.log('Signed message is:')
  console.log(idToken)

  // build and store access token
  const access_token = randomstring.generate(10)
  mongoClient.connect('mongodb://127.0.0.1:27017/', function(err, db) {

    if (err) {
      throw err
    }

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
  console.log('and scope: %s', scopeGranted)

  const tokenResponse = {
    access_token: access_token,
    token_type: 'Bearer',
    scope: scopeGranted,
    id_token: idToken
  }

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

// generate the JWT logout token
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


// perform the actions to logout
async function logout(subject) {

  console.log('logout ...')

  let resolveTokens = new Promise(function(resolve, reject) {

    // query all token of the user
    mongoClient.connect('mongodb://127.0.0.1:27017/', function(err, db) {
      if (err) {
        throw err;
      }
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
  })

  let tokens = await resolveTokens

  async function propagate(token) {

    return new Promise(function(resolve, reject) {

      let logoutClientId = token.client_id
      let logoutClient = getClient(logoutClientId)

      // call clients to logout
      axios.defaults.headers.post['Content-Type'] = 'application/x-www-form-urlencoded'
      axios.post(logoutClient.logoutURL, {
          logout_token: generateLogoutToken(logoutClientId, subject)
        }).then(function(response) {
          console.log('Backchannel logout request send to client %s.', logoutClientId)
          resolve('OK')
        })
        .catch(function(error) {
          console.log('Error: Could not send logout to client %s (%s).', logoutClientId, logoutClient.description)
          resolve('Failed')
        })
    })
  }

  // iterate the token found and call logout on the client
  let receivers = []
  tokens.forEach((token, i) => {
    receivers.push(propagate(token))
  })

  // asnc call all relying parties in parallel
  Promise.all(receivers)

  // delete the assigned sessions
  let destroySessions = new Promise(function(resolve, reject) {

    // delete all http sessions of the user
    mongoClient.connect('mongodb://127.0.0.1:27017/', function(err, db) {
      if (err) {
        throw err;
      }
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
  })

  await destroySessions
  console.log('logout done')
}

// verify signature: 'no key found' error means the signature is invalid.
async function signatureValid(token) {
  let key = await jose.JWK.asKey(publicKey, "pem")
  let result = await jose.JWS.createVerify(key).verify(token)
  console.log('verify: Signed message payload is:')
  console.log(result.payload.toString())
  return JSON.parse(result.payload.toString())
}

/**
 * The OpenID Connect logout
 **/
app.get('/oidc_logout', async (req, res) => {

  console.log('/oidc_logout ...')

  let inToken = req.query.id_token_hint

  if (!inToken) {
    console.log('Error: Missing id token hint.')
    res.status(400).json({
      error: 'Missing id token hint.'
    })
    console.log('/oidc_logout done.')
    return
  }

  const payload = await signatureValid(inToken)

  logout(payload.sub)

  res.render('info', {
    text: 'You are logged out. The OIDC provider deleted the id token' +
      ' and all http sessions assigned to the user.'
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
