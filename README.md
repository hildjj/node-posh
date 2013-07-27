node-posh
=========

PKIX Over Secure HTTP (POSH) tools for node.js.  See http://tools.ietf.org/html/draft-miller-posh-00 for more information.

# Usage

	Usage: genposh [options] [common name]

	Options:
	  --help, -h  Show this message and exit.
	  --out, -o   Directory in which to output files [default: "."]
	  --days, -d  Days of validity for the generated certificate [default: 365]
	  --cert, -c  Use this existing certificate file, rather than creating a new one
