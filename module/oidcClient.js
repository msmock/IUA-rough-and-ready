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

// load the public key of the OIDC provider signature verification
const publicKey = fs.readFileSync('./keys/oidc/public-key.pem')

// helper function for token display
blockFormat = function(s) {
  if (!s) return s
  let blocked = []
  for (let i = 0; i < s.length; i++) {
    blocked.push(s[i])
    if (i > 0 && (i % 70) === 0)
      blocked.push('\n')
  }
  return blocked.join('')
}

// verify signature: 'no key found' error means the signature is invalid.
async function signatureValid(token) {
  let key = await jose.JWK.asKey(publicKey, 'pem')
  let result = await jose.JWS.createVerify(key).verify(token)
  console.log('verify: Signed message payload is:')
  console.log(result.payload.toString())
  return JSON.parse(result.payload.toString())
}

// verify the OIDC token
const isValid = function(token, client_id, issuer) {

  if (!(token.iss === issuer)) {
    console.log('Error: Unexpected issuer. Got %s, expected %s', token.iss, issuer)
    return false
  }

  if ((Array.isArray(token.aud) && !_.contains(token.aud, client_id))) {
    console.log('Error: Client is not contained in aud array.')
    return false
  } else if (!(token.aud === client_id)) {
    console.log('Error: Client id does not match the aud parameter.')
    console.log('Expected %s, but got %s', client_id, token.aud)
    return false
  }

  const now = Math.floor(Date.now() / 1000)

  if (token.iat > now) {
    console.log('Error: Issue date is later than now.')
    return false
  }

  if (token.exp < now) {
    console.log('Error: Token is expired.')
    return false
  }

  return true
}

// oidc server metadata
const serverData = function() {
  return {
    issuer: 'http://localhost:9003/',
    authenticationURL: 'http://localhost:9003/oidc_authenticate',
    authorizationURL: 'http://localhost:9003/oidc_authorize',
    tokenURL: 'http://localhost:9003/oidc_token',
    logoutURL: 'http://localhost:9003/oidc_logout',
    userinfoEndpoint: 'http://localhost:9003/oidc_userinfo'
  }
}

// query the user info endpoint of the OIDC Provider
const UserInfo = function(req, res) {

  console.log('/UserInfo ...')

  // TODO: Check access token lifetime
  if (!req.session.oidc || !req.session.oidc.access_token) {
    res.render('error', {
      error: 'Session expired.'
    })
    console.log('/UserInfo ...')
    return
  }

  console.log('Making user info request.')

  axios.defaults.headers.post['Content-Type'] = 'application/x-www-form-urlencoded'
  axios.defaults.headers.common['Authorization'] = 'Bearer ' + req.session.oidc.access_token

  axios.post(serverData().userinfoEndpoint).then(function(response) {

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

  console.log('/UserInfo done.')
}

//
const LogoutRequest = function(req, res) {

  console.log('/LogoutRequest ...')

  console.log('Http session is:')
  console.log(req.session)

  // redirect to oidc logout
  const authenticateUrl = url.parse(serverData().logoutURL, true)
  delete authenticateUrl.search // this is to get around odd behavior in the node URL library

  // TODO: we don't have a token hint, if we only authenticated via the IUA server
  // in this case we must logout at the IUA server (i.e. discard the iua session)

  // set query parameter state and id_token_hint
  authenticateUrl.query = {
    state: randomstring.generate(10),
    id_token_hint: (req.session.oidc != null) ? req.session.oidc.id_token : null
  }

  console.log('URL call to OpenID Connect server:')
  console.log(url.format(authenticateUrl))

  res.redirect(url.format(authenticateUrl))
  console.log('/LogoutRequest done.')
  return
}

//
const Logout = function(req, res) {

  console.log('/Logout ...')

  console.log('Logout called by OIDC Provider with body:')
  console.log(req.body)

  // logout action shall be implemented here

  console.log('/Logout done.')
  return
}

const Authenticate = function(req, res, oidcClient) {

  console.log('/Authenticate ...')

  const code_verifier = randomstring.generate(43)
  const base64Digest = crypto.createHash('sha256').update(code_verifier).digest('base64')
  const code_challenge = base64url.fromBase64(base64Digest)

  req.session.oidc = {
    code_verifier: code_verifier,
    request: {
      response_type: 'code',
      client_id: oidcClient.clientId,
      redirect_uri: oidcClient.redirectUris[0],
      state: randomstring.generate(10),
      code_challenge: code_challenge,
      code_challenge_method: 'S256',
      scope: oidcClient.scope
    }
  }

  const authenticateUrl = url.parse(serverData().authenticationURL, true)
  delete authenticateUrl.search // this is to get around odd behavior in the node URL library

  authenticateUrl.query = req.session.oidc.request

  console.log('URL call to OpenID Connect server:')
  console.log(url.format(authenticateUrl))
  res.redirect(url.format(authenticateUrl))

  console.log('/Authenticate done.')
}

// called from OIDC Provider with authorization token. Exchanges the
// authorization token to the access token by calling the OIDC Provider tokenURL
async function Callback(req, res, oidcClient) {

  console.log('/Callback ...')

  // error handling
  if (req.query.error) {
    res.render('error', {
      error: req.query.error
    })
    return
  }

  let oidc_session_data = req.session.oidc

  // security check on state. Compare response to session value.
  if (!(req.query.state === oidc_session_data.request.state)) {
    console.log('Error: State mismatch: expected %s got %s', oidc_session_data.request.state, req.query.state)
    res.render('error', {
      error: 'State value did not match.'
    })
    return
  }

  // exchange authorization code to access token
  const headers = {
    contentType: 'application/x-www-form-urlencoded',
    authorization: 'Basic ' + Buffer.from(querystring.escape(oidcClient.clientId) + ':' + querystring.escape(oidcClient.clientSecret)).toString('base64')
  }

  const code = req.query.code

  console.log('Requesting access token for authorization code: %s', code)

  axios.defaults.headers.post['Content-Type'] = headers.contentType
  axios.defaults.headers.common['Authorization'] = headers.authorization

  let response = await axios.post(serverData().tokenURL, {
    grant_type: 'authorization_code',
    code: code,
    code_verifier: oidc_session_data.code_verifier,
    redirect_uri: oidc_session_data.request.redirect_uri
  })

  console.log('received response data:')
  console.log(response.data)

  // access token
  req.session.oidc = {
    access_token: response.data.access_token,
    refresh_token: response.data.refresh_token,
    scope: response.data.scope,
    id_token: response.data.id_token
  }

  const payload = await signatureValid(req.session.oidc.id_token)

  console.log('/Callback: payload is ')
  console.log(payload);

  if (!isValid(payload, oidcClient.clientId, serverData().issuer)) {
    console.log('Error: Invalid token data.')
    res.render('error', {
      error: 'Invalid token data'
    })
    console.log('/Callback done.')
    return
  }
  // return page to display the OpenID Connect session data
  res.render('oidc_info', {
    access_token: req.session.oidc.access_token,
    id_token: blockFormat(req.session.oidc.id_token),
    payload: payload,
    scope: req.session.oidc.scope
  })

  console.log('/Callback done.')

}

// the export declaration
module.exports = {
  serverData,
  Authenticate,
  Callback,
  UserInfo,
  LogoutRequest,
  Logout
}
