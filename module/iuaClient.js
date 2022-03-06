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


const getJWSPayload = function(token) {
  return token ? jose.jws.JWS.parse(token).payloadObj : null
}

// check the token signature with the public key of the IUA Server
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

// validate the iua token
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

// iua server metadata
const serverData = function() {
  return {
    issuer: 'http://localhost:9001/',
    authorizationURL: 'http://localhost:9001/iua_authorize',
    tokenURL: 'http://localhost:9001/iua_token'
  }
}

// the export declaration
module.exports = {
  getJWSPayload,
  signatureValid,
  isValid,
  serverData
}
