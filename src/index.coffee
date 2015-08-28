###
# node-posh #
See [draft-miller-posh](http://tools.ietf.org/html/draft-miller-posh-04)
for more details on PKIX over Secure HTTP (POSH).
###

bb = require 'bluebird'
services = require 'service-parser'

crypto = require 'crypto'
dns = bb.promisifyAll(require 'dns')
events = require 'events'
fs = bb.promisifyAll(require 'fs')
net = require 'net'
tls = require 'tls'

@file = (data, dir, srv, seconds) ->
  fs.statAsync dir
  .then (stats) ->
    if !stats.isDirectory()
      return bb.reject "Invalid directory: #{dir}"
  , ->
    fs.mkdirAsync dir
  .then ->
    s = JSON.stringify
      fingerprints: [
        "sha-1": crypto.createHash('sha1').update(data).digest('base64')
        "sha-256": crypto.createHash('sha256').update(data).digest('base64')
      ]
      expires: seconds
    fn = "#{dir}/posh.#{srv}.json"
    console.error "Writing '#{fn}'"
    fs.writeFileAsync fn, s

class @POSHtls extends events.EventEmitter
  ###
  Make a TLS connection to a given domain on a given service.

  Events:

   * `'connecting', host, port, tls` Connecting on the given host and port.  If
     `tls` is true, a TLS handshake will start as soon as the connection
     finishes.
   * `'error', er` an error was detected.
   * `'connect', socket` the given socket was connected.  If you need to do
     start-tls, do so now, then call @tls_start
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
    @options =
      fallback_port: -1
      start_tls: false
      ca: []
      verbose: false

    for k,v of options ? {}
      @options[k] = v

    if @options.fallback_port == -1
      m = @dns_srv.match /^_([^\.]+)/
      if m
        serv = services.getByName m[1]
        if serv
          @options.fallback_port = serv.port

    # set the defaults
    @host = @dns_domain
    @port = @options.fallback_port
    @wait = null

  resolve: ->
    ###
    Do the SRV resolution.

    * __returns__ a promise that will be
     fulfilled with `host`, `port` when complete.  Ignores DNS errors, returning
     the original domain and fallback port.
    ###
    if !@dns_srv
      return bb.resolve([@host, @port])

    dns.resolveSrvAsync "#{@dns_srv}.#{@dns_domain}"
    .then (addresses) =>
      # TODO: full SRV algorithm
      if addresses.length
        [{name:@host, port:@port}] = addresses
      [@host, @port]
    , (er)->
      [@host, @port]

  _connect_internal: (tls, connector)->
    @resolve().spread (host, port) =>
      @emit 'connecting', host, port, tls
      if @options.verbose
        console.log "Connecting to #{host}:#{port} (TLS: #{tls})"

      @wait = bb.defer()
      @cli = connector host, port

      @cli.on 'error', (er) =>
        @wait.reject er
        @wait = null
      @cli.once 'connect', () =>
        @emit 'connect', tls
      @cli.once 'secureConnect', =>
        @wait.resolve @_check_cert()
        @wait = null
      @cli.on 'data', (data)=>
        if @options.verbose
          console.log 'RECV: ', data.toString('utf-8')
        @emit 'data', data

      @wait.promise

  _check_cert: ()=>
    cert = @cli.getPeerCertificate()
    if @cli.authorized
      @emit 'secure', cert
    else
      @emit 'check', cert
    [@cli.authorized, cert]

  connect: ()->
    ###
    Connect to the domain on the specified service, using either an initially-
    plaintext approach (options.start_tls=true), or an initially-encrypted
    approach (options.start_tls=false).

    * __returns__ a promise
    ###
    if @options.start_tls
      @_connect_internal false, (host, port) ->
        net.connect
          host: host
          port: port
    else
      @_connect_internal true, (host, port) ->
        tls.connect
          host: host
          port: port
          rejectUnauthorized: false

  write: (data, encoding) ->
    if @options.verbose
      console.log "SEND:", data
    @cli.write data, encoding

  end: (data, encoding) ->
    @cli.end(data, encoding)

  start_tls: ()->
    ###
    On the already-connected socket, start a TLS handshake.  This MUST occur
    after the 'connect' event has been called.
    ###

    @cli = tls.connect
      socket: @cli
      servername: @dns_domain
      rejectUnauthorized: false
    , =>
      @wait.resolve @_check_cert()
      @wait = null

    @cli.on 'error', (er) =>
      @wait.reject er
      @wait = null

class @POSHxmpp extends @POSHtls
  constructor: (domain, options={}) ->
    opts =
      fallback_port: options.fallback_port ? 5269
      start_tls: options.start_tls ? true
      ca: options.ca ? []
      server: options.server ? false
    if opts.server
      srv = '_xmpp-server._tcp'
      ns  = 'jabber:server'
    else
      srv = '_xmpp-client._tcp'
      ns  = 'jabber:client'

    super domain, srv, opts

    ss = ''
    @on 'data', (data) =>
      s = data.toString('utf8')
      ss += s
      if ss.match /\<proceed\s/
        @start_tls()
      if ss.match /\<failure\s/
        @wait.reject("start-tls FAILURE")
        @wait = null

    @on 'connect', (tls) =>
      if tls then return
      @write """
<?xml version='1.0'?>
<stream:stream xmlns:stream='http://etherx.jabber.org/streams'
  version='1.0' xml:lang='en'
  to='#{domain}'
  xmlns='#{ns}'>
<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>
""", 'utf-8'
