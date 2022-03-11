# IUA rough and ready
A node project with IUA authentciation client, OpenID Connect Provider, IUA Authorization
Server and a Resource Server, all JavaScript from scratch with mininal dependencies for
educational and testing purposes.

The project uses public and private keys in pem format for signing and signature validation.
To run the apps these certifcates must be generated and stored to folder keys.  

To test copy the code and run npm install to resolve the dependencies. Then run your
terminal and:
- node client,
- node oidcServer,
- node iuaServer,
- node resourceServer.

A cockpit is provided at localhost:9000. You may use alice or bob as user with no password.          

## Project Dependencies

### jsrsasign
Opensource JavaScript cryptographic library supports RSA/RSAPSS/ECDSA/DSA signing/validation, ASN.1, PKCS#1/5/8 private/public key, X.509 certificate, CRL, OCSP, CMS SignedData, TimeStamp and CAdES and JSON Web Signature(JWS)/Token(JWT)/Key(JWK)

see https://kjur.github.io/jsrsasign/

### querystring
Node module providing utilities for parsing and formatting URL query strings. The
querystring API is considered Legacy. While it is still maintained, new code should
use the <URLSearchParams> API instead.

### consolidate
Template engine consolidation library.

### url
Node url library which provides utilities for URL resolution and parsing.

### underscore and underscore.string
Helper functions.

### axios
Asynchronous http call library

### mongodb-memory-server
In memory mongodb

### connect-mongodb-session
Driver to use a mongo db with express session.
