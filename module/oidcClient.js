const express = require("express")
const bodyParser = require('body-parser')
const url = require("url")
const querystring = require('querystring')
const cons = require('consolidate')
const randomstring = require("randomstring")
const jose = require('jsrsasign')
const axios = require('axios')
const session = require('express-session')
const __ = require('underscore')
__.string = require('underscore.string')


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

const getJWSPayload = function(token) {
  return token ? jose.jws.JWS.parse(token).payloadObj : null
}

// check the token signature with the public key of the OIDC Provider
const signatureValid = function(token) {

  const rsaKey = {
    "alg": "RS256",
    "e": "AQAB",
    "n": "p8eP5gL1H_H9UNzCuQS-vNRVz3NWxZTHYk1tG9VpkfFjWNKG3MFTNZJ1l5g_COMm2_2i_YhQNH8MJ_nQ4exKMXrWJB4tyVZohovUxfw-eLgu1XQ8oYcVYW8ym6Um-BkqwwWL6CXZ70X81YyIMrnsGTyTV6M8gBPun8g2L8KbDbXR1lDfOOWiZ2ss1CRLrmNM-GRp3Gj-ECG7_3Nx9n_s5to2ZtwJ1GS1maGjrSZ9GRAYLrHhndrL_8ie_9DS2T-ML7QNQtNkg2RvLv4f0dpjRYI23djxVtAylYK4oiT_uEMgSkc4dxwKwGuBxSO0g9JOobgfy0--FUHHYtRi0dOFZw",
    "kty": "RSA",
    "kid": "authserver"
  }

  const publicKey = jose.KEYUTIL.getKey(rsaKey)
  return jose.jws.JWS.verify(token, publicKey, ['RS256'])
}

// verify the OIDC token
const isValid = function(token, client_id, issuer) {

  if (!(token.iss === issuer)) {
    console.log('Error: Unexpected issuer ', token.issuer)
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

// display the local oidc session data
const Info = function(req, res) {

  console.log('/oidc_info ...')

  if (req.session.oidc) {
    res.render('oidc_info', {
      access_token: req.session.oidc.access_token,
      id_token: blockFormat(req.session.oidc.id_token),
      payload: getJWSPayload(req.session.oidc.id_token),
      scope: req.session.oidc.scope
    })
    console.log('/oidc_info done.')
    return
  }

  // else
  res.render('error', {
    error: 'Session expired.'
  })

  console.log('/oidc_info done.')
  return
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

  // set query parameter state and id_token_hint
  authenticateUrl.query = {
    state: randomstring.generate(10),
    id_token_hint: req.session.oidc.id_token
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

  // TODO logout action shall be implemented here

  console.log('/Logout done.')
  return
}

const Authenticate = function(req, res, oidcClient) {

  console.log("/Authenticate ...")

  /**
  TODO use code challenge method
  *
  from PKCE:
  plain -> code_challenge = code_verifier
  S256 -> code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
  **/
  let code_verifier = randomstring.generate(12)
  req.session.oidc = {
    code_verifier: code_verifier,
    request: {
      response_type: 'code',
      client_id: oidcClient.clientId,
      redirect_uri: oidcClient.redirectUris[0],
      state: randomstring.generate(10),
      code_challenge: code_verifier,
      code_challenge_method: 'plain',
      scope: oidcClient.scope
    }
  }

  const authenticateUrl = url.parse(serverData().authenticationURL, true)
  delete authenticateUrl.search // this is to get around odd behavior in the node URL library

  authenticateUrl.query = req.session.oidc.request

  console.log('URL call to OpenID Connect server:')
  console.log(url.format(authenticateUrl))
  res.redirect(url.format(authenticateUrl))

  console.log("/Authenticate done.")
}

// called from OIDC Provider with authorization token. Exchanges the
// authorization token to the access token by calling the OIDC Provider tokenURL
const Callback = function(req, res, oidcClient) {

  console.log("/Callback ...")

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

  axios.post(serverData().tokenURL, {

      grant_type: 'authorization_code',
      code: code,
      code_verifier: oidc_session_data.code_verifier,
      redirect_uri: oidc_session_data.request.redirect_uri

    }).then(function(response) {

      console.log('received response data:')
      console.log(response.data)

      // access token
      req.session.oidc = {
        access_token: response.data.access_token,
        refresh_token: response.data.refresh_token,
        scope: response.data.scope,
        id_token: response.data.id_token
      }

      if (!signatureValid(req.session.oidc.id_token)) {
        console.log('Error: Invalid signature of token.')
        res.render('error', {
          error: 'Invalid signature of token'
        })
        console.log("/Callback done.")
        return
      }

      console.log('Signature validated.')
      const payload = getJWSPayload(req.session.oidc.id_token)

      if (!isValid(payload, oidcClient.clientId, serverData().issuer)) {
        console.log('Error: Invalid token data.')
        res.render('error', {
          error: 'Invalid token data'
        })
        console.log("/Callback done.")
        return
      }
      // return page to display the OpenID Connect session data
      res.render('oidc_info', {
        access_token: req.session.oidc.access_token,
        id_token: blockFormat(req.session.oidc.id_token),
        payload: payload,
        scope: req.session.oidc.scope
      })

      console.log("/Callback done.")
    })
    .catch(function(error) {
      console.log(error)
      res.render('error', {
        error: error
      })
      console.log("/Callback done.")
      return
    })
}

// the export declaration
module.exports = {
  serverData,
  Info,
  Authenticate,
  Callback,
  UserInfo,
  LogoutRequest,
  Logout
}