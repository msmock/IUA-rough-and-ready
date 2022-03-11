const express = require("express")
const bodyParser = require('body-parser')
const url = require("url")
const querystring = require('querystring')
const cons = require('consolidate')
const randomstring = require("randomstring")
const axios = require('axios')
const session = require('express-session')
const __ = require('underscore')
__.string = require('underscore.string')

const jose = require('node-jose')
const fs = require('fs')

// load the public key of the OIDC provider signature verification
const publicKey = fs.readFileSync('./keys/iua/public-key.pem')

// verify signature: 'no key found' error means the signature is invalid.
async function signatureValid(token) {
  
  console.log('signatureValid ...')

  let key = await jose.JWK.asKey(publicKey, "pem")
  let result = await jose.JWS.createVerify(key).verify(token)

  console.log('verify: Signed message payload is:')
  console.log(result.payload.toString())

  return JSON.parse(result.payload.toString())
  console.log('signatureValid done.')
}

// validate the iua token
const isValid = function(token, client_id, issuer) {

  if (!(token.iss === issuer)) {
    console.log('Error: Unexpected issuer. Expected %s, got %s.', issuer, token.iss)
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
  // getJWSPayload,
  signatureValid,
  isValid,
  serverData
}
