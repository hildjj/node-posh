node-posh
=========

PKIX Over Secure HTTP (POSH) tools for node.js.  See 
http://tools.ietf.org/html/draft-miller-posh-00 for more information.

# Usage

	Usage: genposh [options] [cert filename...]

	Options:
	  --help, -h        Show this message and exit
	  --out, -o         Directory in which to output files             [default: "."]
	  --days, -d        Days of validity for the generated certificate [default: 365]
	  --service, -s     SRV-style service name for the POSH file       [default: "_xmpp._tcp"]
	  --maxcerts, -m    The maximum number of certs to output in the
	                    x5c field.  0 means all.                       [default: 0]
	  --commonname, -c  Create a new certificate, with this common name (multiple ok)

# Installation

	npm install node-posh

# Example

Generate a new certificate that is good for 30 days.  Keep the old certificate 
in the the POSH output to support the roll-over period:

	genposh -d 30 -s _imap._tcp -c localhost old-cert.pem

This will generate a file called `posh._imap._tcp.json` that contains POSH JSON 
that looks like this:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "localhost:Jb9DgTJyJQQuMo0lgEU0FijVaF0",
      "n": "tgN-hrmVCeAz4dCRnsNDaIyYOFIHaRK1zqCURvsiY-NopMFq38qBwOecRso0Xy8qHbUMw7xwvfn2cOAkG4G8k-_Fo55hV_kMZQVIZMOpXVmEsNZ34N9Bj91e_UI_-UK-ejeUwkSxyH9fpPf5L4bZZtGi2_vZl2y-Ik39OV5c5Uc",
      "e": "AQAB",
      "x5c": [
        "MIIBnzCCAQgCCQCLHVds8mHyBDANBgkqhkiG9w0BAQUFADAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMTMwNzI4MDU0MzI3WhcNMTMwODI3MDU0MzI3WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBALYDfoa5lQngM+HQkZ7DQ2iMmDhSB2kStc6glEb7ImPjaKTBat/KgcDnnEbKNF8vKh21DMO8cL359nDgJBuBvJPvxaOeYVf5DGUFSGTDqV1ZhLDWd+DfQY/dXv1CP/lCvno3lMJEsch/X6T3+S+G2WbRotv72ZdsviJN/TleXOVHAgMBAAEwDQYJKoZIhvcNAQEFBQADgYEAi2QwxfUp2xrdBftEsuAxg2LrEaoO+WwvSCPbyUUGU+98/d8+gYqeIybDWDltzGt/ZSZvZstgNsgGPEPeK4M29m6BIZzOhztqZ5GEsnhvSI2Yhg2ZBxP7hmiDkBqPoq6HoX3FVec0ilnLmRU1WDWXwOVLY6Wn7F6hTys9pKSU9aw="
      ]
    },
    {
      "kty": "RSA",
      "kid": "localhost:xpqT5yQpLvdwCeBB6Fydah1rQkE",
      "n": "1l4_n_wO2zOL3BNcAaw_aeVmryoVVRI429mSQ00AcwArW6U02lxM7fuIR-RJe0xl7KtDZBsgZbgK_Y5lCpRHUAuk9ZAsl-gsZIBWQXnyFKVNSV6yxlv3OgE__K9Wfqih1j8SKfPLffnvsXisb979DR-DgvrwxtBj0oJYwI4yUqc",
      "e": "AQAB",
      "x5c": [
        "MIIBnzCCAQgCCQDdbgfPWRJHHTANBgkqhkiG9w0BAQUFADAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMTMwNzI4MDU0MzExWhcNMTMwODI3MDU0MzExWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBANZeP5/8Dtszi9wTXAGsP2nlZq8qFVUSONvZkkNNAHMAK1ulNNpcTO37iEfkSXtMZeyrQ2QbIGW4Cv2OZQqUR1ALpPWQLJfoLGSAVkF58hSlTUlessZb9zoBP/yvVn6oodY/Einzy33577F4rG/e/Q0fg4L68MbQY9KCWMCOMlKnAgMBAAEwDQYJKoZIhvcNAQEFBQADgYEACbIaGqXdRUkrlmjXTyo4Rikh1sYrxtZQL/XSmNw1uwzNPtlwaEziAtLI9HsCfryZ7vwshEy81xcoBCsIu7WJ1xX/iLaVzFOt2bkN3de6UECqPsEaUEXksg2wTCV4ItpAlMNh4Ix/yF5cHwJ91dSvkcEZm2ERr1TPs/BeAHUIHKs="
      ]
    }
  ]
}
```

# API

## Functions
  
### <a name="create">create(certs, maxdepth)</a>
Create a POSH document from a list of certificates.

 * `certs` an array of PEM-encoded certificate chains.  The first certificate
   in each chain will be extracted into the POSH public key information.
 * `maxdepth` the maxiumum number of certificates to use from each chain.
 * returns a [Q](https://github.com/kriskowal/q) promise that will be
   fulfilled with a JavaScript representation (not a JSON string!) of the
   POSH document.

  
### <a name="write">write(dir, service, posh)</a>
Write a file with the given POSH object in a file with the correct name
for the given service.

  * `dir` the directory to write into
  * `service` the SRV record name for the target service.
    Example: "_xmpp-server._tcp"
  * returns a [Q](https://github.com/kriskowal/q) promise that will be
   fulfilled when the file is finished writing

## Classes
  
### <a name="POSH">[POSH](POSH)</a>
    
#### *[extends events.EventEmitter](#events.EventEmitter)*
      
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

#### Instance Methods
      
##### <a name="constructor">constructor(@domain, @srv, options)</a>
Create a POSH connection object

* `domain` connect to the given domain
* `srv` the DNS SRV protocol name to connect with.
  For example, "_xmpp-server._tcp"
* `options` a configuration object
  * `fallback_port` The port to fall back on if SRV fails.  If -1, use
    the port for the given SRV protocol name from /etc/services.  Defaults
    to -1.
  * `start_tls` Don't do TLS immediately after connecting.  Instead, wait
    for a listener for the `connect` event to call `start_tls()`.
  * `ca` An array of zero or more certificate authority (CA) certs to trust
    when making HTTPS calls for POSH certs.
      
##### <a name="get_posh">get\_posh()</a>
Attempt to get the POSH assertion for the domain and SRV protocol
given in the constructor

* __returns__ a [Q](https://github.com/kriskowal/q) promise that will be
 fulfilled with the POSH object when/if it is retrieved.  Rejections of
 this promise usually shouldn't be treated as an error.
      
##### <a name="resolve">resolve()</a>
Do the SRV resolution.

* __returns__ a [Q](https://github.com/kriskowal/q) promise that will be
 fulfilled with `host`, `port` when complete.  Ignores DNS errors, returning
 the original domain and fallback port.
  
##### <a name="connect_plain">connect\_plain()</a>
Connect without starting TLS.  Wait for the `connect` event, then call
`start_tls`.

* __returns__ a [Q](https://github.com/kriskowal/q) promise that will be
 fulfilled with the connected socket.
   
##### <a name="connect_tls">connect\_tls()</a>
Connect to the given serice, and start TLS immediately.

* __returns__ a [Q](https://github.com/kriskowal/q) promise that will be
 fulfilled with the connected socket.
  
##### <a name="start_tls">start\_tls()</a>
On the already-connected socket, start a TLS handshake.  This MUST occur
after the 'connect' event has been called.
  
##### <a name="connect">connect()</a>
Connect to the domain on the specified service, using either an initially-
plaintext approach (options.start_tls=true), or an initially-encrypted
approach (options.start_tls=false).

* __returns__ a [Q](https://github.com/kriskowal/q) promise that will be
 fulfilled with the connected socket.

