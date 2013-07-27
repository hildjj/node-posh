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
  cert:
    description: "Use this existing certificate file, rather than creating a new one"
    alias: 'c'
  service:
    description: "SRV-style service name for the POSH file"
    default: '_xmpp._tcp'
    alias: 's'

argv = optimist.usage('Usage: $0 [options] [common name]', options).argv

if argv.help
  optimist.showHelp()
  process.exit 64

complain = (er) ->
  console.log er
  process.exit 1

hex2base64url = (hex)->
  b64 = new Buffer(hex, 'hex').toString('base64')
  b64.replace(/\=/g, '').replace(/\+/g, '-').replace(/\//g, '_')

gen_posh = (cert)->
  async.parallel [
    (cb)->
      pem.getModulus cert, cb
    (cb)->
      pem.getFingerprint cert, cb
    (cb)->
      pem.readCertificateInfo cert, cb
  ], (er,results)->
    complain er if er

    modulus = hex2base64url results[0].modulus
    fing = results[1].fingerprint.replace /:/g, ''
    fing = hex2base64url fing
    cert = cert.replace /-----[^\n]+\n?/gm, ''
    cert = cert.replace /\n/g, ''
    cn = results[2].commonName
    posh =
      keys: [
        kty: "RSA"
        kid: "#{cn}:#{fing}"
        n:   modulus
        e:   "AQAB"
        x5c: cert
      ]
    json = JSON.stringify posh
    fs.writeFile "#{argv.out}/posh.#{argv.service}.json", json, (er)->
      complain er if er

if argv.cert
  fs.readFile argv.cert, (er, cert)->
    complain er if er
    cert = cert.toString('utf8')
    gen_posh cert
else
  cn = argv._[0] || 'localhost'

  pem.createCertificate
    days: argv.days
    selfSigned: true
    commonName: cn
  , (er, keys)->
    complain er if er

    async.parallel [
      (cb)->
        fs.writeFile "#{argv.out}/#{cn}-key.pem", keys.clientKey, cb
      (cb)->
        fs.writeFile "#{argv.out}/#{cn}.pem", keys.certificate, cb
    ], (er, results)->
      compain er if er
      gen_posh keys.certificate
