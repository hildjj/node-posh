pem = require 'pem'
async = require 'async'
fs = require 'fs'
optimist = require 'optimist'
options =
  help:
    description: "Show this message and exit."
    boolean:true
    alias: 'h'
  out:
    description: "Directory in which to output files"
    string:true
    alias: 'o'
    default:'.'
  days:
    description: "Days of validity for the generated certificate"
    alias: 'd'
    default: 365

argv = optimist.usage('Usage: $0 [options] [common name]', options).argv

if argv.help
  optimist.showHelp()
  process.exit 64

cn = argv._[0] || 'localhost'

hex2base64url = (hex)->
  b64 = new Buffer(hex, 'hex').toString('base64')
  b64.replace(/\=/g, '').replace(/\+/g, '-').replace(/\//g, '_')

pem.createCertificate
  days: argv.days
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
      fs.writeFile "#{argv.out}/#{cn}-key.pem", keys.clientKey, cb
    (cb)->
      fs.writeFile "#{argv.out}/#{cn}.pem", keys.certificate, cb
  ], (er,results)->
    if er
      console.log er
      process.exit 1
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
    fs.writeFile "#{argv.out}/posh._xmpp._tcp.json", json, (er)->
      if er
        console.log er
