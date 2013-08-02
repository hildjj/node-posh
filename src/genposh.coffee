pem = require 'pem'
fs = require 'fs'
posh = require './index'
Q = require 'q'

usage = ()->
  process.stderr.write """
Usage: genposh [options] [cert filename...]

Options:
  --help, -h        Show this message and exit
  --out, -o         Directory in which to output files             [default: "."]
  --days, -d        Days of validity for the generated certificate [default: 365]
  --service, -s     SRV-style service name for the POSH file       [default: "_xmpp-server._tcp"]
  --maxcerts, -m    The maximum number of certs to output in the
                    x5c field.  0 means all.                       [default: 0]
  --commonname, -c  Create a new certificate, with this common name (multiple ok)
"""
  process.exit 64

complain = (er)->
  console.log er
  process.exit 1

class NewCert
  constructor: (@cn)->
    @days = 365
    @dir = '.'

  create: ->
    Q.nfcall(pem.createCertificate,
      days: @days
      selfSigned: true
      commonName: @cn
    ).then (keys)=>
      Q.all([
        Q.nfcall fs.writeFile, "#{@dir}/#{@cn}-key.pem", keys.clientKey
        Q.nfcall fs.writeFile, "#{@dir}/#{@cn}.pem", keys.certificate
      ]).then ()->
        keys.certificate

class FileCert
  constructor: (@fn)->

  create: ->
    Q.nfcall(fs.readFile, @fn).then (data)->
      data.toString 'utf8'

argv =
  help: false
  maxcerts: 0
  service: '_xmpp-server._tcp'
  days: 365
  out: '.'
  certs: []

args = process.argv.slice 2
while args.length
  a = args.shift()
  switch a
    when '-h', '--help' then usage()
    when '-o', '--out' then argv.out = args.shift() || usage()
    when '-d', '--days' then argv.days = parseInt(args.shift()) || usage()
    when '-s', '--service' then argv.service = args.shift() || usage()
    when '-m', '--maxcerts' then argv.maxcerts = parseInt(args.shift()) || usage()
    when '-c', '--commonname'
      cn = args.shift() || usage()
      argv.certs.push(new NewCert cn)
    else
      argv.certs.push(new FileCert a)

for c in argv.certs when c instanceof NewCert
  c.days = argv.days
  c.dir = argv.out

f = argv.certs.map (cert)->
  c.create()
Q.all(f).then (certs)->
  console.log certs
  posh.create(certs, argv.maxcerts).then (json)->
    posh.write argv.out, argv.service, json
, complain
