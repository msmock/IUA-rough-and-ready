const express = require('express')
const url = require('url')
const bodyParser = require('body-parser')
const randomstring = require("randomstring")
const cons = require('consolidate')
const querystring = require('querystring')
const cors = require('cors')
const axios = require('axios')
const __ = require('underscore')
__.string = require('underscore.string')

const iua = require('./module/iuaClient')
const morgan = require('morgan')

// create app
const app = express()
app.use(morgan('short'))

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

app.options('/resource', cors())

// the OAuth secured endpoint to fetch the resource
app.post('/resource', cors(), async (req, res) => {

  console.log('/resource ...')

  // check the auth header first
  const auth = req.headers['authorization']
  let token = auth.slice('bearer '.length)

  const payload = await iua.signatureValid(token)

  console.log('Signature validated.')

  console.log('Access token payload is: ')
  console.log(JSON.stringify(payload, null, 2))

  // verify the token data
  if (!iua.isValid(payload, payload.client_id, iua.serverData().issuer)) {
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

  // policy enforcement comes here

  console.log('Return requested resource.')
  res.status(200).json(resource)
  return
})

// start the server
const server = app.listen(9002, 'localhost', function() {
  console.log('Resource Server is listening at http://%s:%s', server.address().address, server.address().port)
})
