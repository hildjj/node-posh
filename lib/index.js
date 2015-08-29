
/*
 * node-posh #
See [draft-miller-posh](http://tools.ietf.org/html/draft-miller-posh-04)
for more details on PKIX over Secure HTTP (POSH).
 */

(function() {
  var bb, crypto, dns, events, fs, net, services, tls,
    bind = function(fn, me){ return function(){ return fn.apply(me, arguments); }; },
    extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  bb = require('bluebird');

  services = require('service-parser');

  crypto = require('crypto');

  dns = bb.promisifyAll(require('dns'));

  events = require('events');

  fs = bb.promisifyAll(require('fs'));

  net = require('net');

  tls = require('tls');

  this.file = function(data, dir, srv, seconds) {
    return fs.statAsync(dir).then(function(stats) {
      if (!stats.isDirectory()) {
        return bb.reject("Invalid directory: " + dir);
      }
    }, function() {
      return fs.mkdirAsync(dir);
    }).then(function() {
      var fn, s;
      s = JSON.stringify({
        fingerprints: [
          {
            "sha-1": crypto.createHash('sha1').update(data).digest('base64'),
            "sha-256": crypto.createHash('sha256').update(data).digest('base64')
          }
        ],
        expires: seconds
      });
      fn = dir + "/posh." + srv + ".json";
      console.error("Writing '" + fn + "'");
      return fs.writeFileAsync(fn, s);
    });
  };

  this.POSHtls = (function(superClass) {
    extend(POSHtls, superClass);


    /*
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
     */

    function POSHtls(dns_domain, dns_srv, options) {
      var k, m, ref, serv, v;
      this.dns_domain = dns_domain;
      this.dns_srv = dns_srv;
      this._check_cert = bind(this._check_cert, this);

      /*
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
       */
      POSHtls.__super__.constructor.call(this, this);
      this.options = {
        fallback_port: -1,
        start_tls: false,
        ca: [],
        verbose: false
      };
      ref = options != null ? options : {};
      for (k in ref) {
        v = ref[k];
        this.options[k] = v;
      }
      if (this.options.fallback_port === -1) {
        m = this.dns_srv.match(/^_([^\.]+)/);
        if (m) {
          serv = services.getByName(m[1]);
          if (serv) {
            this.options.fallback_port = serv.port;
          }
        }
      }
      this.host = this.dns_domain;
      this.port = this.options.fallback_port;
      this.wait = null;
    }

    POSHtls.prototype.resolve = function() {

      /*
      Do the SRV resolution.
      
      * __returns__ a promise that will be
       fulfilled with `host`, `port` when complete.  Ignores DNS errors, returning
       the original domain and fallback port.
       */
      if (!this.dns_srv) {
        return bb.resolve([this.host, this.port]);
      }
      return dns.resolveSrvAsync(this.dns_srv + "." + this.dns_domain).then((function(_this) {
        return function(addresses) {
          var ref;
          if (_this.options.verbose) {
            console.log("DNS addresses:", addresses);
          }
          if (addresses.length) {
            ref = addresses[0], _this.host = ref.name, _this.port = ref.port;
          }
          return [_this.host, _this.port];
        };
      })(this), (function(_this) {
        return function(er) {
          if (_this.options.verbose) {
            console.log("Continuing after DNS fail:", er);
          }
          return [_this.host, _this.port];
        };
      })(this));
    };

    POSHtls.prototype._connect_internal = function(tls, connector) {
      return this.resolve().spread((function(_this) {
        return function(host, port) {
          _this.emit('connecting', host, port, tls);
          if (_this.options.verbose) {
            console.log("Connecting to " + host + ":" + port + " (TLS: " + tls + ")");
          }
          _this.wait = bb.defer();
          _this.cli = connector(host, port);
          _this.cli.on('error', function(er) {
            _this.wait.reject(er);
            return _this.wait = null;
          });
          _this.cli.once('connect', function() {
            return _this.emit('connect', tls);
          });
          _this.cli.once('secureConnect', function() {
            _this.wait.resolve(_this._check_cert());
            return _this.wait = null;
          });
          _this.cli.on('data', function(data) {
            if (_this.options.verbose) {
              console.log('RECV: ', data.toString('utf-8'));
            }
            return _this.emit('data', data);
          });
          return _this.wait.promise;
        };
      })(this));
    };

    POSHtls.prototype._check_cert = function() {
      var cert;
      cert = this.cli.getPeerCertificate();
      if (this.cli.authorized) {
        this.emit('secure', cert);
      } else {
        this.emit('check', cert);
      }
      return [this.cli.authorized, cert];
    };

    POSHtls.prototype.connect = function() {

      /*
      Connect to the domain on the specified service, using either an initially-
      plaintext approach (options.start_tls=true), or an initially-encrypted
      approach (options.start_tls=false).
      
      * __returns__ a promise
       */
      if (this.options.start_tls) {
        return this._connect_internal(false, function(host, port) {
          return net.connect({
            host: host,
            port: port
          });
        });
      } else {
        return this._connect_internal(true, function(host, port) {
          return tls.connect({
            host: host,
            port: port,
            rejectUnauthorized: false
          });
        });
      }
    };

    POSHtls.prototype.write = function(data, encoding) {
      if (this.options.verbose) {
        console.log("SEND:", data);
      }
      return this.cli.write(data, encoding);
    };

    POSHtls.prototype.end = function(data, encoding) {
      return this.cli.end(data, encoding);
    };

    POSHtls.prototype.start_tls = function() {

      /*
      On the already-connected socket, start a TLS handshake.  This MUST occur
      after the 'connect' event has been called.
       */
      this.cli = tls.connect({
        socket: this.cli,
        servername: this.dns_domain,
        rejectUnauthorized: false
      }, (function(_this) {
        return function() {
          _this.wait.resolve(_this._check_cert());
          return _this.wait = null;
        };
      })(this));
      return this.cli.on('error', (function(_this) {
        return function(er) {
          _this.wait.reject(er);
          return _this.wait = null;
        };
      })(this));
    };

    return POSHtls;

  })(events.EventEmitter);

  this.POSHxmpp = (function(superClass) {
    extend(POSHxmpp, superClass);

    function POSHxmpp(domain, options) {
      var got_data, ns, opts, ref, ref1, ref2, ref3, ref4, srv, ss;
      if (options == null) {
        options = {};
      }
      opts = {
        fallback_port: (ref = options.fallback_port) != null ? ref : 5269,
        start_tls: (ref1 = options.start_tls) != null ? ref1 : true,
        ca: (ref2 = options.ca) != null ? ref2 : [],
        server: (ref3 = options.server) != null ? ref3 : false,
        verbose: (ref4 = options.verbose) != null ? ref4 : false
      };
      if (opts.server) {
        srv = '_xmpp-server._tcp';
        ns = 'jabber:server';
      } else {
        srv = '_xmpp-client._tcp';
        ns = 'jabber:client';
      }
      POSHxmpp.__super__.constructor.call(this, domain, srv, opts);
      ss = '';
      got_data = (function(_this) {
        return function(data) {
          ss += data.toString('utf8');
          if (ss.match(/\<proceed\s/)) {
            _this.removeListener('data', got_data);
            _this.start_tls();
          }
          if (ss.match(/\<failure\s/)) {
            _this.wait.reject("start-tls FAILURE");
            return _this.wait = null;
          }
        };
      })(this);
      this.on('data', got_data);
      this.on('connect', (function(_this) {
        return function(tls) {
          if (tls) {
            return;
          }
          return _this.write("<?xml version='1.0'?>\n<stream:stream xmlns:stream='http://etherx.jabber.org/streams'\n  version='1.0' xml:lang='en'\n  to='" + domain + "'\n  xmlns='" + ns + "'>\n<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>", 'utf-8');
        };
      })(this));
    }

    return POSHxmpp;

  })(this.POSHtls);

  this.POSHsmtp = (function(superClass) {
    extend(POSHsmtp, superClass);

    function POSHsmtp(domain, options) {
      var got_data, opts, ref, ref1, ref2, ref3, ss, state;
      if (options == null) {
        options = {};
      }
      opts = {
        fallback_port: (ref = options.fallback_port) != null ? ref : 20,
        start_tls: (ref1 = options.start_tls) != null ? ref1 : true,
        ca: (ref2 = options.ca) != null ? ref2 : [],
        verbose: (ref3 = options.verbose) != null ? ref3 : false
      };
      POSHsmtp.__super__.constructor.call(this, domain, "_submission._tcp", opts);
      state = 0;
      ss = '';
      got_data = (function(_this) {
        return function(data) {
          ss += data.toString('utf8');
          switch (state) {
            case 0:
              if (ss.match(/^\d+\s[^\n]*\n/m)) {
                ss = '';
                state++;
                return _this.write("EHLO " + domain + "\n", 'utf-8');
              }
              break;
            case 1:
              if (ss.match(/^\d+\s[^\n]*\n/m)) {
                ss = '';
                state++;
                return _this.write('STARTTLS\n', 'utf-8');
              }
              break;
            case 2:
              if (ss.match(/^220\s+[^\n]+$/m)) {
                _this.start_tls();
                return _this.removeListener('data', got_data);
              }
          }
        };
      })(this);
      this.on('data', got_data);
    }

    return POSHsmtp;

  })(this.POSHtls);

  this.POSHimap = (function(superClass) {
    extend(POSHimap, superClass);

    function POSHimap(domain, options) {
      var got_data, opts, ref, ref1, ref2, ref3, ref4, srv, ss, state;
      if (options == null) {
        options = {};
      }
      opts = {
        start_tls: (ref = options.start_tls) != null ? ref : true,
        ca: (ref1 = options.ca) != null ? ref1 : [],
        verbose: (ref2 = options.verbose) != null ? ref2 : false
      };
      if (opts.start_tls) {
        srv = '_imap';
        opts.fallback_port = (ref3 = options.fallback_port) != null ? ref3 : 143;
      } else {
        srv = '_imaps';
        opts.fallback_port = (ref4 = options.fallback_port) != null ? ref4 : 993;
      }
      POSHimap.__super__.constructor.call(this, domain, srv + "._tcp", opts);
      state = 0;
      ss = '';
      got_data = (function(_this) {
        return function(data) {
          ss += data.toString('utf8');
          switch (state) {
            case 0:
              if (ss.match(/^\*\s+OK[^\r]*\r\n/m)) {
                ss = '';
                state++;
                return _this.write("a1 STARTTLS\r\n", 'utf-8');
              }
              break;
            case 1:
              if (ss.match(/^a1\s+OK[^\r]*\r\n/m)) {
                _this.start_tls();
                return _this.removeListener('data', got_data);
              }
          }
        };
      })(this);
      this.on('data', got_data);
    }

    return POSHimap;

  })(this.POSHtls);

}).call(this);
