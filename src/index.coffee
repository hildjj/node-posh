###
# node-posh #
See [draft-miller-posh](http://tools.ietf.org/html/draft-miller-posh-00)
for more details on PKIX over Secure HTTP (POSH).
###

fs = require 'fs'
events = require 'events'
dns = require 'dns'
net = require 'net'
tls = require 'tls'

pem = require 'pem'
Q = require 'q'
request = require 'request'
services = require 'service-parser'

#Q.longStackSupport = true

_hex_to_base64url = (hex)->
  if hex.length % 2
    hex = '0' + hex
  b64 = new Buffer(hex, 'hex').toString('base64')
  b64.replace(/\=/g, '').replace(/\+/g, '-').replace(/\//g, '_')

_cert_to_x5c = (cert,maxdepth=0)->
  ###
  Convert a PEM-encoded certificate to the version used in the x5c element
  of a [JSON Web Key](http://tools.ietf.org/html/draft-ietf-jose-json-web-key).

   * `cert` PEM-encoded certificate chain
   * `maxdepth` The maximum number of certificates to use from the chain.
  ###
  cert = cert.replace(/-----[^\n]+\n?/gm, ',').replace(/\n/g, '')
  cert = cert.split(',').filter (c)->
    c.length > 0

  if maxdepth > 0
    cert = cert.splice 0, maxdepth
  cert

_get_cert_info = (cert)->
  Q.spread [
     Q.nfcall(pem.getModulus, cert)
     Q.nfcall(pem.getFingerprint, cert)
     Q.nfcall(pem.readCertificateInfo, cert)
  ], (modulus, fingerprint, info)->
    info.modulus = _hex_to_base64url modulus.modulus
    info.fingerprint = _hex_to_base64url fingerprint.fingerprint.replace(/:/g, '')
    info

_get_x5c_info = (x5c)->
  cert = (x5c[y..y+63] for y in [0..(x5c.length)] by 64).join '\n'
  """-----BEGIN CERTIFICATE-----
#{c}
-----END CERTIFICATE-----
"""
  _get_cert_info(cert)

_cert_to_jwk = (cert, maxdepth)->
  ###
  Convert a certificate to a
  [JSON Web Key](http://tools.ietf.org/html/draft-ietf-jose-json-web-key)
  representation.

   * `cert` PEM-encoded certificate chain
   * `maxdepth` The maximum number of certificates to use from the chain.
  ###
  _get_cert_info(cert).then (info)->
    # TODO: retrieve exponent from cert, instead of assuming AQAB.
    kty: "RSA"
    kid: "#{info.commonName}:#{info.fingerprint}"
    n:   info.modulus
    e:   "AQAB"
    x5c: _cert_to_x5c cert, maxdepth

exports.create = (certs, maxdepth)->
  ###
  Create a POSH document from a list of certificates.

   * `certs` an array of PEM-encoded certificate chains.  The first certificate
     in each chain will be extracted into the POSH public key information.
   * `maxdepth` the maxiumum number of certificates to use from each chain.
   * __returns__ a [Q](https://github.com/kriskowal/q) promise that will be
     fulfilled with a JavaScript representation (not a JSON string!) of the
     POSH document.
  ###
  unless Array.isArray(certs)
    certs = [certs]
  if certs.length == 0
    throw new Error 'No certs specified'

  p = certs.map (c)->
    _cert_to_jwk c, maxdepth
  Q.all(p).then (all)->
    keys: all

exports.write = (dir, service, posh)->
  ###
  Write a file with the given POSH object in a file with the correct name
  for the given service.

    * `dir` the directory to write into
    * `service` the SRV record name for the target service.
      Example: "_xmpp-server._tcp"
    * __returns__ a [Q](https://github.com/kriskowal/q) promise that will be
     fulfilled when the file is finished writing
  ###
  Q.nfcall fs.writeFile, "#{dir}/posh.#{service}.json", JSON.stringify(posh)


class POSH extends events.EventEmitter
  ###
  Make a POSH-verified connection to a given domain on a given service.

  Events:

   * `'posh request', url` about to request a POSH document at the given URL
   * `'no posh', er` No POSH document could be retrieved.  Not really an error.
   * `'connecting', host, port, tls` Connecting on the given host and port.  If
     `tls` is true, a TLS handshake will start as soon as the connection
     finishes.
   * `'error', er` an error was detected.
   * `'connect', socket` the given socket was connected
   * `'secure', service_cert, posh_document` the connection is secure
      either by RFC 6125 or POSH.  The posh_document is null if the service_cert
      was valid via RFC 6125.
   * `'insecure', service_cert, posh_document` the connection could not be
      determined to be secure.  The posh_document is null if it could not be
      retrieved.
  ###
  constructor: (@dns_domain, @dns_srv, options)->
    ###
    Create a POSH connection object

    * `dns_domain` connect to the given domain
    * `dns_srv` the DNS SRV protocol name to connect with.
      For example, "_xmpp-server._tcp"
    * `options` a configuration object
      * `fallback_port` The port to fall back on if SRV fails.  If -1, use
        the port for the given SRV protocol name from /etc/services.  Defaults
        to -1.
      * `start_tls` Don't do TLS immediately after connecting.  Instead, wait
        for a listener for the `connect` event to call `start_tls()`.
      * `ca` An array of zero or more certificate authority (CA) certs to trust
        when making HTTPS calls for POSH certs.
    ###
    super @
    @options = {
      fallback_port: -1
      start_tls: false
      ca: []
    }
    for k,v of options ? {}
      @options[k] = v

    if @options.fallback_port == -1
      m = @dns_srv.match /^_([^\.]+)/
      if m
        serv = services.getByName m[1]
        if serv
          @options.fallback_port = serv.port

    @posh_url = "https://#{@dns_domain}/.well-known/posh.#{@dns_srv}.json"
    @host = @dns_domain
    @port = @options.fallback_port

  get_posh: ->
    ###
    Attempt to get the POSH assertion for the domain and SRV protocol
    given in the constructor

    * __returns__ a [Q](https://github.com/kriskowal/q) promise that will be
     fulfilled with the POSH object when/if it is retrieved.  Rejections of
     this promise usually shouldn't be treated as an error.
    ###
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
    ###
    Do the SRV resolution.

    * __returns__ a [Q](https://github.com/kriskowal/q) promise that will be
     fulfilled with `host`, `port` when complete.  Ignores DNS errors, returning
     the original domain and fallback port.
    ###
    Q.nfcall(dns.resolveSrv, "#{@dns_srv}.#{@dns_domain}")
    .then (addresses)=>
      # TODO: full SRV algorithm
      if addresses.length
        [{name:@host, port:@port}] = addresses
      [@host, @port]
    , (er)->
      [@host, @port]

  _connect_internal: (tls, connector)->
    @posh = @get_posh()

    @resolve().spread (host, port) =>
      @emit 'connecting', host, port, tls
      d = Q.defer()

      @cli = connector host, port

      @cli.on 'error', (er)=>
        @emit 'error', er
        d.reject er
      @cli.once 'connect', ()=>
        @emit 'connect', @cli
        d.resolve @cli
      d.promise

  connect_plain: ()->
    ###
    Connect without starting TLS.  Wait for the `connect` event, then call
    `start_tls`.

    * __returns__ a [Q](https://github.com/kriskowal/q) promise that will be
     fulfilled with the connected socket.
    ###
    @_connect_internal false, (host, port)->
      net.connect
        host: host
        port: port

  _check_cert: ()=>
    cert = @cli.getPeerCertificate()
    if @cli.authorized
      @emit 'secure', cert
      Q.resolve true, cert
    else
      d = Q.defer()
      @posh.then (pjson) =>
        if pjson?
          modu = _hex_to_base64url cert.modulus
          exp = _hex_to_base64url cert.exponent
          for k in pjson.keys
            # TODO: get the k5c and proess with pem
            if (k.n == modu) and (k.e == exp)
              @emit 'secure', cert, pjson
              return d.resolve true, cert, pjson
        @emit 'insecure', cert, pjson
        d.resolve false, cert, pjson
      , (er)=>
        @emit 'insecure', cert
        d.resolve false, cert

      d.promise

  connect_tls: ()->
    ###
    Connect to the given serice, and start TLS immediately.

    * __returns__ a [Q](https://github.com/kriskowal/q) promise that will be
     fulfilled with the connected socket.
    ###
    @_connect_internal true, (host, port)->
      tls.connect
        host: @host
        port: @port
        rejectUnauthorized: false
    .then @_check_cert

  start_tls: ()->
    ###
    On the already-connected socket, start a TLS handshake.  This MUST occur
    after the 'connect' event has been called.
    ###

    @cli = tls.connect
      socket: @cli
      rejectUnauthorized: false
      servername: @dns_domain
    , @_check_cert

    # TODO: cause this error, and see if it fires twice.  Bet it does.
    @cli.on 'error', (er) =>
      @emit 'error', er

  connect: ()->
    ###
    Connect to the domain on the specified service, using either an initially-
    plaintext approach (options.start_tls=true), or an initially-encrypted
    approach (options.start_tls=false).

    * __returns__ a [Q](https://github.com/kriskowal/q) promise that will be
     fulfilled with the connected socket.
    ###
    if @options.start_tls
      @connect_plain()
    else
      @connect_tls()

exports.POSH = POSH
