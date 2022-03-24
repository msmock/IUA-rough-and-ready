const express = require('express')
const bodyParser = require('body-parser')
const url = require('url')
const querystring = require('querystring')
const cons = require('consolidate')
const randomstring = require('randomstring')
const axios = require('axios')
const session = require('express-session')
const __ = require('underscore')
__.string = require('underscore.string')

const jose = require('node-jose')
const fs = require('fs')

const crypto = require('crypto')
const base64url = require('base64url')

const oidc = require('./module/oidcClient')
const iua = require('./module/iuaClient')

const morgan = require('morgan')

// create app
const app = express()
app.use(morgan('short'))

// session handling
app.use(session({
  secret: randomstring.generate(12),
  name: 'client_cookie',
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
app.set('views', 'files/client')

// helper function for token display
let blockFormat = function(s) {
  if (!s) return s
  let blocked = []
  for (let i = 0; i < s.length; i++) {
    blocked.push(s[i])
    if (i > 0 && (i % 70) === 0)
      blocked.push('\n')
  }
  return blocked.join('')
}

// The OpenID Connect metadata of this client
const oidcClient = {
  clientId: 'oidc-client-2',
  clientSecret: 'oidc-client-secret-2',
  redirectUris: ['http://localhost:9000/oidc_callback'],
  logoutURL: ['http://localhost:9000/oidc_logout'],
  scope: 'openid profile email address phone',
  description: 'My client application.'
}

// iua client metadata
const iuaClient = {
  client_id: 'iua-client-1',
  client_secret: 'iua-client-secret-1',
  redirect_uris: ['http://localhost:9000/iua_callback'],
  scope: 'openid read write purpose_of_use subject_role person_id'
}

// display the OpenID Connect user info data of the current session
app.get('/oidc_userinfo', oidc.UserInfo)

// redirects the user agent to the OpenID Connect authorization endpoint
app.get('/oidc_authenticate', function(req, res) {
  oidc.Authenticate(req, res, oidcClient)
})

// exchange the auth code to the access token via the backchannel
app.get('/oidc_callback', async (req, res) => {
  oidc.Callback(req, res, oidcClient)
})

// RP initated logout. Sends the logout to the OIDC Provider
app.get('/oidc_logout_request', oidc.LogoutRequest)

// OIDC Provider initated backchannel logout
app.post('/oidc_logout', oidc.Logout)

// display iua session data
app.get('/iua_info', function(req, res) {

  res.render('iua_info', {
    token: blockFormat(req.session.iua.access_token),
    payload: iua.getJWSPayload(req.session.iua.access_token),
    scope: req.session.iua.scope
  })

})

// redirects the user agent to the IUA authorization endpoint to request the IUA authorization code.
app.get('/iua_authorize', function(req, res) {

  console.log('/iua_authorize ...')

  const code_verifier = randomstring.generate(43)
  const base64Digest = crypto.createHash('sha256').update(code_verifier).digest('base64')
  const code_challenge = base64url.fromBase64(base64Digest)

  req.session.iua = {
    code_verifier: code_verifier,
    request: {
      response_type: 'code',
      client_id: iuaClient.client_id,
      redirect_uri: iuaClient.redirect_uris[0],
      state: randomstring.generate(10),
      code_challenge: code_challenge,
      code_challenge_method: 'S256',
      scope: iuaClient.scope // TODO set the values for the epr scopes (purpose_of_use={...}, subject_role={...}, person_id=CX)
    }
  }

  const authorizeUrl = url.parse(iua.serverData().authorizationURL, true)
  delete authorizeUrl.search // this is to get around odd behavior in the node URL library

  authorizeUrl.query = req.session.iua.request

  console.log('URL call to authorization server:')
  console.log(url.format(authorizeUrl))

  res.redirect(url.format(authorizeUrl))

  console.log('/iua_authorize done')
})

// called after access token retrieval
async function onAccessToken(req, res, response) {

  req.session.iua = {
    access_token: response.data.access_token,
    scope: response.data.scope
  }

  const payload = await iua.signatureValid(req.session.iua.access_token)

  console.log('Signature validated.')

  if (!iua.isValid(payload, iuaClient.client_id, iua.serverData().issuer)) {
    console.log('Error: Invalid token data.')
    res.render('error', {
      error: 'Invalid token data'
    })
    console.log('/iua_callback done.')
    return
  }

  // display IUA session data page in the user agent
  res.render('iua_info', {
    token: blockFormat(req.session.iua.access_token),
    payload: payload,
    scope: req.session.iua.scope
  })
}

// The redirect url to transfer the authorization code and exchange to access token
app.get('/iua_callback', function(req, res) {

  console.log('/iua_callback ...')

  // error handling
  if (req.query.error) {
    res.render('error', {
      error: req.query.error
    })
    console.log('/iua_callback done.')
    return
  }

  if (!req.session.iua || !req.session.iua.request) {
    console.log('Error: No request data stored at http session.');
    res.render('error', {
      error: 'Invalid request to callback.'
    })
    console.log('/iua_callback done.')
    return
  }

  // security check on state. Compare response to session value.
  const resState = req.query.state
  if (resState === req.session.iua.request.state) {
    console.log('State value matches: expected %s got %s', req.session.iua.request.state, resState)
  } else {
    console.log('Error: State do not match: expected %s got %s', req.session.iua.request.state, resState)
    res.render('error', {
      error: 'State value did not match.'
    })
    console.log('/iua_callback done.')
    return
  }

  const code = req.query.code

  console.log('Requesting access token for authorization code: %s', code)

  // exchange authorization code to access token
  const headers = {
    contentType: 'application/x-www-form-urlencoded',
    authorization: 'Basic ' + Buffer.from(querystring.escape(iuaClient.client_id) + ':' + querystring.escape(iuaClient.client_secret)).toString('base64')
  }

  axios.defaults.headers.post['Content-Type'] = headers.contentType
  axios.defaults.headers.common['Authorization'] = headers.authorization

  axios.post(iua.serverData().tokenURL, {

      grant_type: 'authorization_code',
      code: code,
      code_verifier: req.session.iua.code_verifier,
      redirect_uri: iuaClient.redirect_uri

    }).then(function(response) {

      console.log('received response data:')
      console.log(response.data)
      onAccessToken(req, res, response)
      console.log('/iua_callback done.')

    })
    .catch(function(error) {
      console.log(error)
      res.status(401).end()
      console.log('/iua_callback done.')
    })
})

// backchannel call to query the resource server
app.get('/iua_fetch_resource', function(req, res) {

  console.log('/iua_fetch_resource')

  if (!req.session.iua || !req.session.iua.access_token) {
    console.log('Error: IUA session is expired.')
    res.render('error', {
      error: 'The IUA session is expired.'
    })
    return
  }

  console.log('Making resource request ...')

  axios.defaults.headers.post['Content-Type'] = 'application/x-www-form-urlencoded'
  axios.defaults.headers.common['Authorization'] = 'Bearer ' + req.session.iua.access_token

  // resource server metadata
  const resourceUrl = 'http://localhost:9002/resource'

  axios.post(resourceUrl).then(function(response) {

      console.log('received response data:')
      console.log(response.data)
      res.render('data', {
        resource: response.data
      })
      return

    })
    .catch(function(error) {
      console.log(error)
      res.render('error', {
        error: 'Server returned error response: ' + error
      })
    })
})

// serves the authorization server metadata
app.get('/', function(req, res) {
  res.render('index', {
    oidcClient: oidcClient,
    oidcServer: oidc.serverData(),
    iuaClient: iuaClient,
    iuaServer: iua.serverData()
  })
})

app.use('/', express.static('files/client'))

const server = app.listen(9000, 'localhost', function() {
  console.log('OAuth Client is listening at http://%s:%s', server.address().address, server.address().port)
})
