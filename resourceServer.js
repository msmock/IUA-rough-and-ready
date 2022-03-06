const express = require("express")
const url = require("url")
const bodyParser = require('body-parser')
const randomstring = require("randomstring")
const cons = require('consolidate')
const querystring = require('querystring')
const jose = require('jsrsasign')
const cors = require('cors')
const axios = require('axios')
const __ = require('underscore')
__.string = require('underscore.string')

const app = express()

app.use(bodyParser.json())
app.use(bodyParser.urlencoded({
  extended: true
}))

app.engine('html', cons.underscore)
app.set('view engine', 'html')
app.set('views', 'files/resourceServer')
app.use('/', express.static('files/resourceServer'))
app.set('json spaces', 1)
app.use(cors())

// the test resource
const resource = {
  "name": "Protected medical resource served by the mhealth resource server.",
  "description": "This data has been protected by IUA (OAuth 2.1)"
}

const iuaServer = {
  issuer: 'http://localhost:9001/'
}

/**
 * check the id token signature with the iua server public key
 **/
var signatureValid = function(token) {

  const rsaKey = {
    "alg": "RS256",
    "e": "AQAB",
    "n": "p8eP5gL1H_H9UNzCuQS-vNRVz3NWxZTHYk1tG9VpkfFjWNKG3MFTNZJ1l5g_COMm2_2i_YhQNH8MJ_nQ4exKMXrWJB4tyVZohovUxfw-eLgu1XQ8oYcVYW8ym6Um-BkqwwWL6CXZ70X81YyIMrnsGTyTV6M8gBPun8g2L8KbDbXR1lDfOOWiZ2ss1CRLrmNM-GRp3Gj-ECG7_3Nx9n_s5to2ZtwJ1GS1maGjrSZ9GRAYLrHhndrL_8ie_9DS2T-ML7QNQtNkg2RvLv4f0dpjRYI23djxVtAylYK4oiT_uEMgSkc4dxwKwGuBxSO0g9JOobgfy0--FUHHYtRi0dOFZw",
    "kty": "RSA",
    "kid": "IUA Server"
  }

  const publicKey = jose.KEYUTIL.getKey(rsaKey)
  return jose.jws.JWS.verify(token, publicKey, ['RS256'])
}

/**
 * deserialize the JWS token and return the payload
 **/
var getJWSPayload = function(token) {
  const payload = jose.jws.JWS.parse(token)
  return payload.payloadObj
}

/**
 * verify an oauth compliant token. It takes the expected client_id and issuer as argument.
 **/
var isValid = function(payload, issuer) {

  if (!(payload.iss === issuer)) {
    console.log('Error: Unexpected issuer ', payload.issuer)
    return false
  }

  const now = Math.floor(Date.now() / 1000)

  if (payload.iat > now) {
    console.log('Error: Issue date is later than now.')
    return false
  }

  if (payload.exp < now) {
    console.log('Error: Token is expired.')
    return false
  }

  return true
}


app.options('/resource', cors())

// the OAuth secured endpoint to fetch the resource
app.post("/resource", cors(), function(req, res) {

  console.log('/resource ...')

  // check the auth header first
  const auth = req.headers['authorization']
  let token = auth.slice('bearer '.length)

  if (! signatureValid(token)){
    console.log('Error: Invalid token signature.')
    res.status(400).render('error', {
      error: 'Invalid token signature'
    })
    return
  }

  let payload = getJWSPayload(token)

  console.log('Access token payload is: ')
  console.log(JSON.stringify(payload, null, 2))

  // verify the token data
  if (!isValid(payload, iuaServer.issuer)) {
    console.log('Error: Invalid token data.')
    res.status(400).render('error', {
      error: 'Invalid token data'
    })
    console.log("/resource done.")
    return
  }

  // check if the scope authorizes the action
  let scope = payload.scope
  if (!__.string.include(scope, 'read')){
    console.log('Error: Scope does not cover read access.')
    res.status(200).json('Unauthorized: Scope granted does not cover read access.')
    console.log("/resource done.")
    return
  }

  // TODO policy enforcement comes here

  console.log('Return requested resource.')
  res.status(200).json(resource)
  return
})

/**
 *
 **/
const server = app.listen(9002, 'localhost', function() {
  const host = server.address().address
  const port = server.address().port
  console.log('OAuth Resource Server is listening at http://%s:%s', host, port)
})
