# Certomancer

<p align="center">
  <img width="300" height="300" src="images/certomancer.svg" alt="logo">
</p>

![status](https://github.com/MatthiasValvekens/certomancer/workflows/pytest/badge.svg)
[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/MatthiasValvekens/certomancer.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/MatthiasValvekens/certomancer/context:python)

Quickly construct, mock & deploy PKI test configurations using simple declarative configuration.
Includes CRL, OCSP and time stamping service provisioning.

Install with `python setup.py install`. See `example.yml` for an example config file, and
[below](#Documentation) for more detailed documentation.

Requires Python 3.7 or later.

## Quick start

```bash
$ pip install 'certomancer[web-api,pkcs12]' 
$ certomancer --config example.yml animate
```

This will run the Certomancer Animator WSGI app on your local machine, behind a development web
server. Point your browser to `http://localhost:9000` and take a look around.
For more information, see the [documentation](#Documentation) below.

## Features

 * Certomancer's core APIs are stateless: the same request should always return the same result.
   This property makes it very useful for automated testing.
 * Declarative, YAML-based configuration.
 * Minimal input validation, so you can generate deliberately broken certificates if you need to.
 * ``requests-mock`` integration.
 * Ultra-lightweight WSGI application: the Certomancer Animator serves CRLs, OCSP responses, 
   timestamps and more. This component requires Werkzeug, and optionally Jinja2 for the index view.
   Other than a web server and WSGI application server, there are no application dependencies.
 * Plugin framework to support arbitrary certificate / CRL extensions and additional services.
   These plugins are compatible with the WSGI and ``requests-mock`` integrations without
   additional configuration.
* Certomancer is composable: since the Certomancer Animator is a bare-bones WSGI application,
  you can plug it into whatever web application framework you want with minimal overhead.
  Hence, for particularly complicated scenarios where the plugin API or existing integrations aren't
  sufficient, it is very easy to use Certomancer as a library, or wrap it as a component
  of some other WSGI application.
 * With [pyca/cryptography](https://github.com/pyca/cryptography) installed, Certomancer can also
   output PKCS#12 files if your tests require those.

## Non-features

Certomancer is a testing tool for developers that write software to interface with public-key
infrastructure. **It is *NOT* intended to be used to manage production PKI deployments.**
Certomancer is very much garbage-in garbage-out, and happily ignores validation & 
security best practices in favour of allowing you to abuse your codebase in the worst possible ways.
Consider yourself warned.


## Documentation

 * [Configuration](docs/config.md)
 * [CLI commands](docs/cli.md)
 * [Plugin API](docs/plugins.md)
 * [Deploying Certomancer](docs/deploy.md)
