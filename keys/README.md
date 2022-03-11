## Open SSL commands

generate private key
- openssl genrsa -out private-key.pem 2048

generate the public key
- openssl rsa -in private-key.pem -pubout -out public-key.pem

generate self signed certificate
- openssl req -new -x509 -key private-key.pem -out cert.pem -days 360

show certificate content
- openssl x509 -noout -text -in cert.pem

## Hint:

generate a private key with passphrase
- openssl genrsa -des3 -out private.pem 2048

To remove the pass phrase on an RSA private key:
- openssl rsa -in key.pem -out keyout.pem

To encrypt a private key using triple DES:
- openssl rsa -in key.pem -des3 -out keyout.pem

To convert a private key from PEM to DER format:
- openssl rsa -in key.pem -outform DER -out keyout.der

To print out the components of a private key to standard output:
- openssl rsa -in key.pem -text -noout

To just output the public part of a private key:
- openssl rsa -in key.pem -pubout -out pubkey.pem

Output the public part of a private key in RSAPublicKey format:
- openssl rsa -in key.pem -RSAPublicKey_out -out pubkey.pem
