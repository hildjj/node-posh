posh = require '..'
fs = require 'fs'
Q = require 'q'

usage = ()->
  process.stderr.write """
Usage: xmpp.coffee [options] domain...

Options:
  --help, -h        Show this message and exit
  --ca, -c          PEM-encoded certificate authority cert to trust

"""
  process.exit 64

args = process.argv.slice 2
ca = []
domain = []
while args.length
  a = args.shift()
  switch a
    when '-h', '--help' then usage()
    when '-c', '--ca' then ca.push(args.shift() || usage())
    else
      domain.push a

unless domain.length then usage()

Q.all(ca.map (c)->
  Q.nfcall fs.readFile, c).then (certs)->
    for d in domain
      console.log "Connecting to #{domain}"
      p = new posh.POSH d, '_xmpp-client._tcp',
        fallback_port: 5222
        start_tls: true
        ca: certs

      p.on 'error', (er)->
        console.log 'ERROR', er

      p.on 'posh request', (url)->
        console.log "Requesting POSH from #{url}"

      p.on 'connecting', (host, port)->
        console.log "Connecting to #{host}:#{port}"

      p.on 'secure', ->
        console.log 'secure'

      p.on 'insecure', ->
        console.log 't insecure', arguments

      p.on 'no posh', (er)->
        console.log 'NO POSH', er

      p.on 'connect', (sock)->
        console.log 'connected'
        ss = ''
        got_data = (data)->
          s = data.toString('utf8')
          console.log "RECV:", s
          ss += s
          if ss.match /\<proceed\s+xmlns=['"]urn:ietf:params:xml:ns:xmpp-tls['"]\/\>$/
            sock.removeListener 'data', got_data
            p.start_tls()

        sock.on 'data', got_data
        out = """
<?xml version='1.0'?>
<stream:stream
    to='#{d}'
    version='1.0'
    xml:lang='en'
    xmlns='jabber:server'
    xmlns:stream='http://etherx.jabber.org/streams'>
<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>
"""
        console.log "SEND:", out
        sock.write out

      p.connect()
