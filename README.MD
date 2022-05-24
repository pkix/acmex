<h1 align="center">
  <br>ACMEX<br>
</h1>

<h4 align="center">An ACME client with DigiCert CA.</h4>

## Features

- Automated certificate enrollment without manual hands on 
- Continuous monitoring for certificate lifecycle management, with automated certificate renewal to keep certificates are always valid

## Getting Started
1. Get your ACME registered KID and HMAC parameters through CertCentral Automation/ACME portal
2. Replace the KID and HMAC values with systemd service in default configuration template
3. Using linux systemd service to monitor the TLS certificate, it will renew the certificate when it close to expire with renewal parameter has given.
```
# acmex.service

[Service]
Type=simple
User=root
Restart=on-failure
LimitNOFILE=102400

# NOTE: change to your KID, HMAC and domains
Environment="KID=your-kid"
Environment="your-hmac-key"
ExecStart=/usr/bin/acmex-linux -domains=your-domain -dir=/etc/web/your-domain/

```

## Command-line Tool
Also the command line program works for issuing new certificate, as the following example.

1. Command-line examples
```
Usage: acme-darwin -domains=example.com -renew=3 -issue=false
  -domains string
    	Domains that you wanted to secure, e.g. example.com
  -issue
    	Issue the new certificate now, default: false
  -renew int
    	Renewal period for certificate, default: 3 days (default 3)
  -saveto string
    	Where do you want to save certificate to, e.g. /etc/web/your-domain/ 
```

2. Issuing a new TLS certificate
```
KID=your-kid HMAC="your-hmac-key" /usr/bin/acmex-linux -domains=your-domain -dir=/etc/web/your-domain/  -issue=true
```

<!-- ## Release
[Release](https://github.com/) -->


## Credits

* [eggsampler/acme](https://github.com/eggsampler/acme)

## License

This software is released under the MIT license.