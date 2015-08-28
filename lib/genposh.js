(function() {
  var bb, fs, pkg, posh;

  pkg = require('../package.json');

  bb = require('bluebird');

  fs = bb.promisifyAll(require('fs'));

  posh = require('./index');

  this.fromCert = function(argv) {
    return fs.readFileAsync(argv.cert, 'utf-8').then(function(data) {
      data = data.replace(/^.*-----BEGIN CERTIFICATE-----/, '');
      data = data.replace(/-----END CERTIFICATE-----.*/, '');
      data = data.replace(/\s+/g, '');
      data = new Buffer(data, 'base64');
      return posh.file(data, argv.out, argv.srv, argv.time);
    });
  };

  this.fromSocket = function(argv) {
    var p, ref, srv;
    srv = (ref = argv.srv) != null ? ref : argv.port;
    switch (argv.starttls) {
      case 'xmpp':
        p = new posh.POSHxmpp(argv.domain, {
          server: !!argv.srv.match(/_xmpp-server/),
          verbose: argv.verbose
        });
        break;
      case 'smtp':
        p = new posh.POSHsmtp(argv.domain, {
          verbose: argv.verbose
        });
        break;
      default:
        p = new posh.POSHtls(argv.domain, argv.srv, {
          fallback_port: argv.port,
          verbose: argv.verbose
        });
    }
    return p.connect().spread(function(ok, cert) {
      return posh.file(cert.raw, argv.out, srv, argv.time);
    });
  };

  this.parse = function(args) {
    var argv, opt, p;
    args = args != null ? args : process.argv.slice(2);
    opt = require('nomnom').printer(function(str, code) {
      var c;
      c = code || 64;
      if (c) {
        console.error(str);
      } else {
        console.log(str);
      }
      return process.exit(c);
    }).options({
      version: {
        abbr: 'V',
        flag: true,
        help: 'Print version and exit',
        callback: function() {
          return pkg.version;
        }
      },
      verbose: {
        abbr: 'v',
        flag: true,
        help: 'Print the Start-TLS protocol sent and received'
      },
      cert: {
        position: 0,
        help: 'PEM-encoded certificate file'
      },
      domain: {
        abbr: 'd',
        metavar: 'DOMAIN',
        help: 'Domain to connect to'
      },
      out: {
        abbr: 'o',
        metavar: 'DIRECTORY',
        help: 'Output directory',
        "default": '.'
      },
      port: {
        abbr: 'p',
        metavar: 'PORT',
        help: 'Fallback port if SRV fails',
        callback: function(port) {
          if (!parseInt(port)) {
            return 'PORT must be an integer';
          }
        }
      },
      srv: {
        abbr: 's',
        metavar: 'SERVICE',
        help: 'SRV-style service name'
      },
      starttls: {
        metavar: 'protocol',
        help: 'Use the given start-TLS protocol',
        choices: ['xmpp', 'smtp']
      },
      time: {
        abbr: 't',
        metavar: 'SECONDS',
        help: 'Seconds of validity',
        "default": 24 * 60 * 60
      }
    }).script('genposh').help('You must either specify a certificte file or a DOMAIN.\nIf connecting to a DOMAIN, you must specify a PORT or a SERVICE.');
    argv = opt.nom(args);
    if (argv.cert != null) {
      p = this.fromCert(argv);
    } else {
      if (!argv.domain || (!argv.port && !argv.srv)) {
        opt.print(opt.getUsage());
      }
      p = this.fromSocket(argv);
    }
    return p.then(function() {
      return process.exit(0);
    }, function(er) {
      console.log(er);
      return process.exit(1);
    });
  };

}).call(this);
