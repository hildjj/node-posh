pkg = require '../package.json'
bb = require 'bluebird'
fs = bb.promisifyAll(require 'fs')
posh = require './index'

@fromCert = (argv) ->
  fs.readFileAsync argv.cert, 'utf-8'
  .then (data) ->
    data = data.replace /^.*-----BEGIN CERTIFICATE-----/, ''
    data = data.replace /-----END CERTIFICATE-----.*/, ''
    data = data.replace /\s+/g, ''
    data = new Buffer data, 'base64'
    posh.file data, argv.out, argv.srv, argv.time

@fromSocket = (argv) ->
  srv = argv.srv ? argv.port
  switch argv.starttls
    when 'xmpp'
      opts =
      p = new posh.POSHxmpp argv.domain,
        server: !!argv.srv.match /_xmpp-server/
        verbose: argv.verbose
      p.connect().spread (ok, cert) ->
        posh.file cert.raw, argv.out, srv, argv.time
    else
      p = new posh.POSHtls argv.domain, argv.srv,
        fallback_port: argv.port
        verbose: argv.verbose
      p.connect().spread (ok, cert) ->
        posh.file cert.raw, argv.out, srv, argv.time

@parse = (args) ->
  args = args ? process.argv.slice(2)
  opt = require('nomnom')
    .printer (str, code) ->
      c = code || 64
      if c
        console.error str
      else
        console.log str
      process.exit c
    .options
      version:
        abbr: 'V'
        flag: true,
        help: 'Print version and exit',
        callback: -> "version 1.2.4"
      vebose:
        abbr: 'v'
        flag: true
        help: 'Print the Start-TLS protocol sent and received'
      cert:
        position: 0
        help: 'PEM-encoded certificate file'
      domain:
        abbr: 'd'
        metavar: 'DOMAIN'
        help: 'Domain to connect to'
      out:
        abbr: 'o'
        metavar: 'DIRECTORY'
        help: 'Output directory'
        default: '.'
      port:
        abbr: 'p'
        metavar: 'PORT'
        help: 'Fallback port if SRV fails'
        callback: (port) ->
          if !parseInt(port)
            'PORT must be an integer'
      srv:
        abbr: 's'
        metavar: 'SERVICE'
        help: 'SRV-style service name'
      starttls:
        metavar: 'protocol'
        help: 'Use the given start-TLS protocol'
        choices: ['xmpp']
      time:
        abbr: 't'
        metavar: 'SECONDS'
        help: 'Seconds of validity'
        default: 24*60*60
    .script 'genposh'
    .help '''
You must either specify a certificte file or a DOMAIN.
If connecting to a DOMAIN, you must specify a PORT or a SERVICE.'''

  argv = opt.nom(args)

  if argv.cert?
    p = @fromCert argv
  else
    if !argv.domain or (!argv.port and !argv.srv)
      opt.print opt.getUsage()
    p = @fromSocket argv

  p.then ->
    process.exit 0
  , (er) ->
    console.log er
    process.exit 1
