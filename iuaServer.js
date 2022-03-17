const express = require('express')
const url = require('url')
const bodyParser = require('body-parser')
const randomstring = require('randomstring')
const cons = require('consolidate')
const querystring = require('querystring')
const axios = require('axios')
const session = require('express-session')
const __ = require('underscore')
__.string = require('underscore.string')

const jose = require('node-jose')
const fs = require('fs')

const crypto = require("crypto")
const base64url = require("base64url")

const oidc = require('./module/oidcClient')

const app = express()

// load the private key for signing
const privateKey = fs.readFileSync('./keys/iua/private-key.pem')

// container to cache request data from authorization to token request
const iuaCache = {}

// session handling
app.use(session({
  secret: randomstring.generate(10),
  name: 'iua_session_cookie',
  saveUninitialized: true,
  cookie: {
    maxAge: 5 * 60 * 1000 // 5 minutes
  },
  resave: false
}))

app.use(bodyParser.json())
app.use(bodyParser.urlencoded({
  extended: true
}))

app.engine('html', cons.underscore)
app.set('view engine', 'html')
app.set('views', 'files/iuaServer')
app.set('json spaces', 1)

// authorization server information
const authServer = {
  issuer: 'http://localhost:9001/',
  authorizationURL: 'http://localhost:9001/iua_authorize',
  tokenURL: 'http://localhost:9001/iua_token'
}

const resourceServer = {
  url: 'http://localhost:9002/'
}

// client registration data
const clients = [{
    clientId: 'iua-client-1',
    clientSecret: 'iua-client-secret-1',
    redirectUris: ['http://localhost:9000/iua_callback'],
    scope: 'openid read write purpose_of_use subject_role person_id',
    description: 'My client application'
  },
  {
    clientId: 'iua-client-2',
    clientSecret: 'iua-client-secret-2',
    redirectUris: ['http://localhost:9010/iua_callback'],
    scope: 'openid read write purpose_of_use subject_role person_id',
    description: 'Some other client application'
  },
  {
    clientId: 'smart-client-1',
    clientSecret: 'smart-client-secret-1',
    redirectUris: ['http://localhost:8080/iua_callback'],
    scope: 'openid read write launch purpose_of_use subject_role person_id',
    description: 'A SMART on FHIR client application'
  }
]

const getClient = function(clientId) {
  return __.find(clients, function(client) {
    return client.clientId === clientId
  })
}

const getCallerCredentials = function(resourceId) {
  return __.find(credentials, function(resource) {
    return resource.resource_id === resourceId
  })
}

// serves the authorization server metadata
app.get('/', function(req, res) {
  res.render('index', {
    clients: clients,
    authServer: authServer
  })
})

// oidc authoriztaion client metadata
const oidcClient = {
  clientId: 'oidc-client-1',
  clientSecret: 'oidc-client-secret-1',
  redirectUris: ['http://localhost:9001/oidc_callback'],
  logoutURL: ['http://localhost:9001/oidc_logout'],
  scope: 'openid profile',
  description: 'This IUA Server.'
}

// authentication endpoint
app.get('/iua_authenticate', function(req, res) {
  oidc.Authenticate(req, res, oidcClient)
})

// The endpoint the user agent is redirected to by the OIDC Provider
app.get("/oidc_callback", function(req, res) {
  oidc.Callback(req, res, oidcClient)
})

// URL called by the OpenID Connect Provider to induce logout
app.post('/oidc_logout', oidc.Logout)

// called to authorize the client access
const onUserInfo = function (req, res, userInfo){

    console.log('onUserInfo ...');

    req.session.oidc.user = userInfo

    // return error, if no authenticated user is stored on the session
    if (!req.session.oidc || !req.session.oidc.user){
      console.log('Error: No authenticated user assigned to session.')
      res.render('error', {
        error: 'No authenticated user assigned to session'
      })
      console.log('onUserInfo done.')
      return
    }

    let client = getClient(req.query.client_id)

    if (!client) {
      console.log('Unknown client %s', req.query.client_id)
      res.render('error', {
        error: 'Unknown client'
      })
      console.log('onUserInfo done.')
      return
    }

    if (!__.contains(client.redirectUris, req.query.redirect_uri)) {
      console.log('Mismatched redirect URI, expected %s got %s', client.redirectUris, req.query.redirect_uri)
      res.render('error', {
        error: 'Invalid redirect URI'
      })
      console.log('onUserInfo done..')
      return
    }

    let rscope = req.query.scope ? req.query.scope.split(' ') : undefined
    let cscope = client.scope ? client.scope.split(' ') : undefined

    // client asked for a scope not declared on registration
    if (__.difference(rscope, cscope).length > 0) {
      let urlParsed = url.parse(req.query.redirect_uri)
      delete urlParsed.search // this is a weird behavior of the URL library
      urlParsed.query = urlParsed.query || {}
      urlParsed.query.error = 'invalid_scope'
      res.redirect(url.format(urlParsed))
      console.log('onUserInfo done.')
      return
    }

    let code_challenge = req.query.code_challenge
    let code_challenge_method = req.query.code_challenge_method

    // else show page to resource owner to authorize scopes
    res.render('approve', {
      client: client,
      scope: rscope,
      code_challenge: code_challenge,
      code_challenge_method: code_challenge_method
    })

    console.log('onUserInfo done.');
}

// expects autorization requests from the user agent
app.get('/iua_authorize', function(req, res) {

  console.log('/iua_authorize ...')

  // store request query to http session
  req.session.iua = {
    query: req.query
  }

  // get the user from OIDC user info url
  console.log('Making user info request ...')

  axios.defaults.headers.post['Content-Type'] = 'application/x-www-form-urlencoded'
  axios.defaults.headers.common['Authorization'] = 'Bearer ' + req.session.oidc.access_token

  axios.post(oidc.serverData().userinfoEndpoint).then(function(response) {
      console.log('User info response:')
      console.log(response.data)
      onUserInfo(req, res, response.data)
    })
    .catch(function(error) {
      console.log(error)
      res.render('error', {
        error: 'Server returned error response: ' + error
      })
    })

  console.log('/iua_authorize done.')
  return
})

// present the UI to authorize client applications
app.post('/iua_approve', function(req, res) {

  console.log('/iua_approve ...')

  // there is no matching request stored at session
  if (!req.session.iua || !req.session.iua.query) {
    console.log('No matching authorization request')
    res.render('error', {
      error: 'No matching authorization request'
    })
    console.log('/iua_approve done.')
    return
  }

  let query = req.session.iua.query
  console.log('/iua_approve query is ' + JSON.stringify(query))

  // resource owner denied access
  if (!req.body.approve) {
    let urlParsed = url.parse(query.redirect_uri)
    delete urlParsed.search // this is a weird behavior of the URL library
    urlParsed.query = urlParsed.query || {}
    urlParsed.query.error = 'access_denied'
    res.redirect(url.format(urlParsed))
    console.log('/iua_approve done.')
    return
  }

  // we got a response type we don't understand
  if (!(query.response_type === 'code')) {
    let urlParsed = url.parse(query.redirect_uri)
    delete urlParsed.search // this is a weird behavior of the URL library
    urlParsed.query = urlParsed.query || {}
    urlParsed.query.error = 'unsupported_response_type'
    res.redirect(url.format(urlParsed))
    console.log('/iua_approve done.')
    return
  }

  // user approved access
  let code = randomstring.generate(10)
  let code_challenge = req.body.code_challenge

  let scope = __.filter(__.keys(req.body), function(s) {
      return __.string.startsWith(s, 'scope_')
    })
    .map(function(s) {
      return s.slice('scope_'.length)
    })

  let client = getClient(query.client_id)
  let cscope = client.scope ? client.scope.split(' ') : undefined

  // client asked for a scope not declared at registration
  if (__.difference(scope, cscope).length > 0) {
    let urlParsed = url.parse(query.redirect_uri)
    delete urlParsed.search // this is a weird behavior of the URL library
    urlParsed.query = urlParsed.query || {}
    urlParsed.query.error = 'invalid_scope'
    res.redirect(url.format(urlParsed))
    console.log('/iua_approve done.')
    return
  }

  // check if we have the user data stored at the session
  if (!req.session.oidc || !req.session.oidc.user) {
    console.log('Error: Missing data of the authenticated user.')
    res.render('error', {
      error: 'Missing user data.'
    })
    console.log('/iua_approve done.')
    return
  }

  // save the code and request for later
  iuaCache[code] = {
    request: query,
    scope: scope,
    user: req.session.oidc.user
  }

  let urlParsed = url.parse(query.redirect_uri)
  delete urlParsed.search // this is a weird behavior of the URL library

  urlParsed.query = urlParsed.query || {}
  urlParsed.query.code = code
  urlParsed.query.state = query.state

  res.redirect(url.format(urlParsed))

  console.log('/iua_approve done.')
  return
})

// generate the JWT access token
function generateTokens(req, res, clientId, user, scope) {

  console.log('/generateTokens ...')

  // the person data are taken from the OpenID Connect token
  const ihe_iua = {
    subject_name: user.name,
    subject_role: {
          system: 'urn:oid:2.16.756.5.30.1.127.3.10.6',
          code: 'PAT'
      },
      purpose_of_use: {
          system: 'urn:uuid:2.16.756.5.30.1.127.3.10.5',
          code: 'NORM',
      },
    home_community_id: 'e155b3d3-5dae-4ef4-8f5a-b86761299a9c',
    person_id: '761337610411353650^^^&amp;2.16.756.5.30.1.127.3.10.3&amp;ISO'
  }

  const ch_epr = {
    user_id: '761337610411353650',
    user_id_qualifier: 'urn:e-health-suisse:2015:epr-spid'
  }

  const jwsTokenPayload = {
    iss: 'http://localhost:9001/',
    sub: user.sub,
    client_id: clientId,
    aud: clientId, // TODO verify
    jti: randomstring.generate(10),
    scope: scope.join(' '),
    exp: Math.floor(Date.now() / 1000) + (5 * 60),
    iat: Math.floor(Date.now() / 1000),
    extensions: {
      ihe_iua: ihe_iua,
      ch_epr: ch_epr
    }
  }

  console.log('IUA Access token payload is:')
  console.log(jwsTokenPayload)

  return jwsTokenPayload
  console.log('/generateTokens done.')
}

// called by the client application via backchannel.
app.post('/iua_token', async (req, res) => {

  console.log('/iua_token ...')

  // check if the client uses http basic authorization
  let auth = req.headers['authorization']

  if (!auth) {
    console.log('Error: Authorization header missing.')
    res.status(401).json({
      error: 'Authorization header missing'
    })
    console.log('/iua_token done.')
    return
  }

  const clientCredentials = Buffer.from(auth.slice('basic '.length), 'base64').toString().split(':')
  const clientId = querystring.unescape(clientCredentials[0])
  const clientSecret = querystring.unescape(clientCredentials[1])

  const client = getClient(clientId)

  // check if the client is known
  if (!client) {
    console.log('Error: Unknown client %s', clientId)
    res.status(401).json({
      error: 'Unknown client'
    })
    console.log('/iua_token done.')
    return
  }

  // authenticate client
  if (client.clientSecret != clientSecret) {
    console.log('Mismatched client secret, expected %s got %s', client.clientSecret, clientSecret)
    res.status(401).json({
      error: 'Mismatched client secret'
    })
    console.log('/iua_token done.')
    return
  }

  // verify grant type
  if (!(req.body.grant_type === 'authorization_code')) {
    console.log('Unsupported grant type %s', req.body.grant_type)
    res.status(400).json({
      error: 'Unsupported grant type'
    })
    console.log('/iua_token done.')
  }

  // check if we have a iua session for the authorization code
  let sessionData = iuaCache[req.body.code]

  if (!sessionData) {
    console.log('Unknown authorization code, %s', req.body.code)
    res.status(400).json({
      error: 'Unknown authorization code'
    })
    console.log('/iua_token done.')
    return
  }

  // remove the session
  delete iuaCache[req.body.code]

  // check if the session is assigned to the same client
  if (!(sessionData.request.client_id === clientId)) {
    console.log('No registered session for this client_id. Expected %s got %s', sessionData.request.client_id, clientId)
    res.status(400).json({
      error: 'No registered session for this client'
    })
    console.log('/iua_token done.')
    return
  }

  const code_verifier = req.body.code_verifier
  const base64Digest = crypto.createHash("sha256").update(code_verifier).digest("base64")
  const code_challenge = base64url.fromBase64(base64Digest)

  // verify the code challenge matches the code verifier
  if (sessionData.request.code_challenge != code_challenge) {
    console.log('Invalid code challenge. Expected %s, got %s', sessionData.request.code_challenge, code_challenge)
    res.status(400).json({
      error: 'Invalid code challenge!'
    })
    console.log('/iua_token done.')
    return
  }

  // get user from oidc user info response
  let user = sessionData.user

  // no error, thus
  const tokenPayload = generateTokens(req, res, clientId, user, sessionData.scope)

  // read private key and sign. This creates the header as well
  let key = await jose.JWK.asKey(privateKey, "pem")

  // format: flattened or compact
  let format = {
    format: 'compact'
  }

  let payload = JSON.stringify(tokenPayload)

  let iuaToken = await jose.JWS.createSign(format, key).update(payload).final()

  console.log('Signed message is:')
  console.log(iuaToken)

  let cscope = sessionData.scope.join(' ')

  console.log('Issuing iua access token with scope = %s', cscope)

  const token_response = {
    access_token: iuaToken,
    token_type: 'Bearer',
    scope: cscope
  }

  res.status(200).json(token_response)
  console.log('Issued iua access token for authorization code %s', req.body.code)
  console.log('/iua_token done.')
  return
})

app.use('/', express.static('files/iuaServer'))

const server = app.listen(9001, 'localhost', function() {
  const host = server.address().address
  const port = server.address().port
  console.log('IUA Authorization Server is listening at http://%s:%s', host, port)
})
