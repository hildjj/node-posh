async = require 'async'
pem = require 'pem'
fs = require 'fs'

hex_to_base64url = (hex)->
  b64 = new Buffer(hex, 'hex').toString('base64')
  b64.replace(/\=/g, '').replace(/\+/g, '-').replace(/\//g, '_')

exports.cert_to_x5c = cert_to_x5c = (cert,maxdepth=0)->
  cert = cert.replace(/-----[^\n]+\n?/gm, ',').replace(/\n/g, '')
  cert = cert.split(',').filter (c)->
    c.length > 0

  if maxdepth > 0
    cert = cert.splice 0, maxdepth
  cert

exports.cert_to_jwk = cert_to_jwk = (cert, maxdepth, cb)->
  async.parallel [
    (c)->
      pem.getModulus cert, c
    (c)->
      pem.getFingerprint cert, c
    (c)->
      pem.readCertificateInfo cert, c
  ], (er,results)->
    cb er if er

    [{modulus:modulus},{fingerprint:fing},{commonName:cn}] = results
    modulus = hex_to_base64url modulus
    fing = hex_to_base64url fing.replace(/:/g, '')
    cert = cert_to_x5c cert, maxdepth

    cb null,
      kty: "RSA"
      kid: "#{cn}:#{fing}"
      n:   modulus
      e:   "AQAB"
      x5c: cert

exports.create = (certs, maxdepth, cb)->
  if certs.length == 0
    return cb new Error 'No certs specified'
  async.map certs, (item, c)->
    cert_to_jwk item, maxdepth, c
  , (er, results)->
    return cb er if er
    cb null,
      keys: results

exports.write = (dir, service, posh, cb)->
  fs.writeFile "#{dir}/posh.#{service}.json", JSON.stringify(posh), cb

