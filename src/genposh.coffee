pem = require 'pem'
async = require 'async'
fs = require 'fs'

argv = process.argv.slice(2)
cn = argv[0] || 'localhost'

hex2base64url = (hex)->
  b64 = new Buffer(hex, 'hex').toString('base64')
  b64.replace(/\=/g, '').replace(/\+/g, '-').replace(/\//g, '_')

pem.createCertificate
  days: 1
  selfSigned: true
  commonName: cn
, (err, keys)->
  if err
    console.log err
    return
  async.parallel [
    (cb)->
      pem.getModulus keys.certificate, cb
    (cb)->
      pem.getFingerprint keys.certificate, cb
    (cb)->
      fs.writeFile "#{cn}-key.pem", keys.clientKey, cb
    (cb)->
      fs.writeFile "#{cn}.pem", keys.certificate, cb
  ], (er,results)->
    modulus = hex2base64url results[0].modulus
    fing = results[1].fingerprint.replace /:/g, ''
    fing = hex2base64url fing
    cert = keys.certificate.replace /-----[^\n]+\n?/gm, ''
    cert = cert.replace /\n/g, ''
    posh =
      keys: [
        kty: "RSA"
        kid: "#{cn}:#{fing}"
        n:   modulus
        e:   "AQAB"
        x5c: cert
      ]
    json = JSON.stringify posh
    fs.writeFile "posh._xmpp._tcp.json", json, (er)->
      if er
        console.log er
