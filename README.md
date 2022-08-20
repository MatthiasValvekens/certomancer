# Certomancer

<p align="center">
  <img width="300" height="300" src="images/certomancer.svg" alt="logo">
</p>

![status](https://github.com/MatthiasValvekens/certomancer/workflows/pytest/badge.svg)
[![PyPI version](https://img.shields.io/pypi/v/certomancer)](https://pypi.org/project/certomancer/)
![Python versions](https://shields.io/pypi/pyversions/certomancer)
[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/MatthiasValvekens/certomancer.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/MatthiasValvekens/certomancer/context:python)
[![Total alerts](https://img.shields.io/lgtm/alerts/g/MatthiasValvekens/certomancer.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/MatthiasValvekens/certomancer/alerts/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

Quickly construct, mock & deploy PKI test configurations using simple declarative configuration.
Includes CRL, OCSP and time stamping service provisioning.

Requires Python 3.7 or later.

## Quick start

Certomancer is [available on PyPI](https://pypi.org/project/certomancer/). See `example.yml` for an example config file.

```bash
$ pip install 'certomancer[web-api,pkcs12]' 
$ certomancer --config example.yml animate
```

This will run the Certomancer Animator WSGI app on your local machine, behind a development web
server. Point your browser to `http://localhost:9000` and take a look around.
For more information, see the [documentation](#Documentation) below.


## Installing the development version

To build and install an (unreleased) development version, you can proceed as follows.

```bash
$ git clone https://github.com/MatthiasValvekens/certomancer
$ cd certomancer
$ python -m build
$ pip install dist/certomancer*.whl
```


## Demo

There's a demo on asciinema.org, demonstrating some of the core features of Certomancer. See link below.

[![asciicast](https://asciinema.org/a/406798.svg)](https://asciinema.org/a/406798)


## FOSDEM '22 talk

I gave a lightning talk on testing & mocking PKI services in the [Testing & Automation devroom](https://fosdem.org/2022/schedule/track/testing_and_automation/) at [FOSDEM 2022](https://fosdem.org/2022/). Certomancer was (of course) featured in the presentation.
If you want to learn more, or watch the recording, have a look at [the talk page](https://fosdem.org/2022/schedule/event/mockery_of_trust/) for further info. Slides are included as well.


## Features

 * Certomancer's core APIs are stateless: the same request should always return the same result.
   This property makes it very useful for automated testing.
   * Note that "the same result" does not necessarily mean "byte-for-byte equal". 
     This is because some signing schemes (like ECDSA) involve random nonces. In addition to that,
     time is also a factor in certain cases (but Certomancer does permit time manipulation).
 * Declarative, YAML-based configuration.
 * Minimal input validation, so you can generate deliberately broken certificates if you need to.
 * ``requests-mock`` integration.
 * Attribute certificate support (`0.7.0` and up)
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
 * With [python-pkcs11](https://github.com/danni/python-pkcs11) installed, Certomancer can write
   keys and certificates to PKCS#11 tokens as well.

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
