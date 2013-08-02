fs = require 'fs'
events = require 'events'
dns = require 'dns'
net = require 'net'
tls = require 'tls'

pem = require 'pem'
Q = require 'q'
request = require 'request'
services = require 'service-parser'

Q.longStackSupport = true

hex_to_base64url = (hex)->
  if hex.length % 2
    hex = '0' + hex
  b64 = new Buffer(hex, 'hex').toString('base64')
  b64.replace(/\=/g, '').replace(/\+/g, '-').replace(/\//g, '_')

exports.cert_to_x5c = cert_to_x5c = (cert,maxdepth=0)->
  cert = cert.replace(/-----[^\n]+\n?/gm, ',').replace(/\n/g, '')
  cert = cert.split(',').filter (c)->
    c.length > 0

  if maxdepth > 0
    cert = cert.splice 0, maxdepth
  cert

cert_to_jwk = (cert, maxdepth)->
  Q.spread [
     Q.nfcall(pem.getModulus, cert)
     Q.nfcall(pem.getFingerprint, cert)
     Q.nfcall(pem.readCertificateInfo, cert)
  ], (modulus, fingerprint, info)->
    modulus = hex_to_base64url modulus.modulus
    fing = hex_to_base64url fingerprint.fingerprint.replace(/:/g, '')
    cn = info.commonName
    cert = cert_to_x5c cert, maxdepth

    kty: "RSA"
    kid: "#{cn}:#{fing}"
    n:   modulus
    e:   "AQAB"
    x5c: cert

exports.create = (certs, maxdepth)->
  unless Array.isArray(certs)
    certs = [certs]
  if certs.length == 0
    throw new Error 'No certs specified'

  p = certs.map (c)->
    cert_to_jwk c, maxdepth
  Q.all(p)

exports.write = (dir, service, posh)->
  Q.nfcall fs.writeFile, "#{dir}/posh.#{service}.json", JSON.stringify(posh)


class POSH extends events.EventEmitter
  constructor: (options)->
    super @
    @options = {
      domain: null
      srv: null
      fallback_port: -1
      startTLS: false
      ca: []
    }
    for k,v of options ? {}
      @options[k] = v

    if @options.fallback_port == -1
      m = @options.srv.match /^_([^\.]+)/
      if m
        serv = services.getByName m[1]
        if serv
          @options.fallback_port = serv.port

    @posh_url = "https://#{@options.domain}/.well-known/posh.#{@options.srv}.json"
    @host = @options.domain
    @port = @options.fallback_port
    @posh = @get_posh()

  get_posh: ->
    @emit 'posh request', @posh_url
    Q.nfcall(request,
      url: @posh_url
      followRedirect: false
      ca: @options.ca)
    .then (resp)=>
      status = resp[0].statusCode
      if status != 200
        er = new Error "HTTP error #{status}"
        @emit 'no posh', er
        Q.reject er
      else
        @posh_json = JSON.parse resp[1]
    , (er)=>
      @emit 'no posh', er
      Q.reject new Error 'No POSH HTTP server'

  resolve: ->
    Q.nfcall(dns.resolveSrv, "#{@options.srv}.#{@options.domain}")
    .then (addresses)=>
      if addresses.length
        [{name:@host, port:@port}] = addresses
      [@host, @port]

  connect_plain: ()->
    @emit 'connecting', @host, @port, false
    d = Q.defer()

    @cli = net.connect
      host: @host
      port: @port

    emit_error_reject = (er)=>
      @emit er
      d.reject er

    @cli.once 'error', emit_error_reject
    @cli.once 'connect', ()=>
      @cli.removeListener 'error', emit_error_reject
      @emit 'connected', @cli
      d.resolve()
    d.promise

  connect_tls: ()->
    @emit 'connecting', @host, @port, true
    d = Q.defer()

    @cli = tls.connect
      host: @host
      port: @port
      rejectUnauthorized: false

    emit_error_reject = (er)=>
      @emit er
      d.reject er

    @cli.once 'error', emit_error_reject
    @cli.once 'connect', ()=>
      @cli.removeListener 'error', emit_error_reject
      @emit 'connected', @cli
      d.resolve()
    d.promise

  start_tls: ()->
    console.log 'Start TLS'
    d = Q.defer()

    @cli = tls.connect
      socket: @cli
      rejectUnauthorized: false
      servername: @dns_domain
    , (er) =>
      if @cli.authorized
        @emit 'secure'
      else
        @posh.then (pjson) =>
          if pjson?
            cert = @cli.getPeerCertificate()
            modu = hex_to_base64url cert.modulus
            exp = hex_to_base64url cert.exponent
            for k in pjson.keys
              if (k.n == modu) and (k.e == exp)
                @emit 'secure'
                return true
          @emit 'insecure', cert, pjson
        , (er)=>
          @emit 'insecure', @cli.getPeerCertificate()


    @cli.on 'error', (er) =>
      @emit 'error', er

  connect: ()->
    @resolve().then =>
      if @options.startTLS
        @connect_plain()
      else
        @connect_tls()
    , (er)->
      @emit 'error', er

exports.POSH = POSH
