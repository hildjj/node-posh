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