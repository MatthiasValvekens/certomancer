# Certomancer

Quickly construct, mock & deploy PKI test configurations using simple declarative configuration. Includes CRL, OCSP and time stamping service provisioning.

Install with `python setup.py install`, and see `example.yml` for an example config file. The CLI comes with a built-in help function (although it isn't very helpful at this stage).


*Warning:*  This is a testing tool for developers that write software to interface with public-key infrastructure. It is *NOT* intended to function as management software for production PKI deployments. Certomancer is very much garbage-in garbage-out, and happily ignores validation & security best practices in favour of allowing you to abuse your codebase in the worst possible ways. Consider yourself warned.
