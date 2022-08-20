# Certomancer CLI


*Note:* Certomancer's CLI was built with [Click](https://click.palletsprojects.com/en/7.x/api/).
As such, it comes with a built-in help function that can be accessed by `certomancer --help`.

## Role of the CLI in Certomancer

In principle, you can spin up a Certomancer instance on a server running nginx and uWSGI without
ever needing to touch its CLI. That being said, the CLI provides a number of useful shortcuts
that'll make testing your code less cumbersome. It can be used to

 - launch a Certomancer Animator instance locally, behind a development server;
 - generate certificates & CRLs without requiring an operational Animator instance at all.

In particular, the CLI allows you to use Certomancer as a certificate generation tool without
actually deploying any of its 'live' components.

The `certomancer` script currently has six subcommands:

 * `animate`: run the Certomancer Animator behind a development server
 * `summon`: create and output a single certificate for a Certomancer PKI architecture
 * `mass-summon`: create and output all certificates for a Certomancer PKI architecture
 * `necronomicon`: create and output a CRL
 * `seance`: generate OCSP responses
 * `alch`: write keys and certificates to a PKCS#11 token

## Core config flags

The following flags should be passed before any subcommands.

| Flag | Argument | Use |
| ---- | -------- | --- |
| `--version` | none | Show the version and exit. |
| `--config` | filename | YAML file to load the [configuration](config.md) from. The default is `certomancer.yml` |
| `--key-root` | dirname | Root folder for paths to keys. The default is the folder containing the configuration file. |
| `--extra-config-root` | dirname | Folder to look for external [PKI architecture files](config.md#pki-architecture-definitions). The default is the folder containing the configuration file. |
| `--no-external-config` | none | Disable external PKI architecture files altogether. |


## Running the Animator locally

Running `certomancer animate` will launch a local instance of Certomancer Animator with a
bare-bones development web server supplied by Werkzeug.
It takes the following arguments.

| Flag | Argument | Use |
| ---- | -------- | --- |
| `--port` | number | Set the port number to listen on. The default is 9000. |
| `--no-web-ui` | none | Disable the web UI and only expose the "core" API. |
| `--no-time-override` | none | Disable per-request time override functionality. |

About the last flag: by default, a test client making requests to an Animator instance can include
the `X-Certomancer-Fake-Time` header with an ISO 8601 datetime to tell Certomancer to simulate
a particular point in time when preparing a response for the request. If left out, the current time
will be used. Passing the `--no-time-override` flag turns off this feature.


## Generating single certificates 

Extracting a single certificate from a Certomancer PKI architecture is done through the
`certomancer summon` command. Its general structure is

```
certomancer summon PKI_ARCH CERT_LABEL [OUTPUT]
```

Here `PKI_ARCH` refers to a PKI architecture defined in the configuration file, `CERT_LABEL`
to the label of a certificate that is part of said PKI architecture, and `OUTPUT` is the (optional)
name of the file to write the output to. If not specified, data will be written to standard output.

The `summon` subcommand takes the following flags and options.

| Flag | Argument | Use |
| ---- | -------- | --- |
|`--ignore-tty` | none | Never try to prevent binary data from being written to stdout, even if stdout appears to be a tty. |
|`--as-pfx` | none | Output a PFX (PKCS #12) file that bundles the certificate with the corresponding chain of issuance and private key, if available. |
|`--pfx-pass` | string | Set the passphrase for the PFX file. |
|`--no-pem` | none | Do not PEM-armour the certificate, just output its raw DER encoding. |

Note: PKCS#12 support requires the `cryptography` library to be installed.


## Generating many certificates

Extracting all certificates from a Certomancer PKI architecture can be done through the
`certomancer mass-summon` command. Its general structure is

```
certomancer mass-summon PKI_ARCH OUTPUT
```

Here `PKI_ARCH` refers to a PKI architecture defined in the configuration file, and `OUTPUT` is the
name of the file or directory to write the output to.
If the `cryptography` library is available, Certomancer will also create PKCS #12 (PFX) files for
each certificate.

The `mass-summon` subcommand takes the following flags and options.

| Flag | Argument | Use |
| ---- | -------- | --- |
|`--flat` | none | Do not group certificates by issuer. |
|`--archive` | none | Write the certificates to a `.zip` archive instead of a directory. |
|`--no-pfx` | string | Do not attempt to generate PKCS#12 files.|
|`--pfx-pass` | string | Set the passphrase for the PFX files to be generated. |
|`--no-pem` | none | Do not PEM-armour the certificates, just output their raw DER encoding. |


## Generating CRLs


To generate a CRL from the CLI, use the `certomancer necronomicon` subcommand.
Its general structure is

```
certomancer necronomicon PKI_ARCH CRL_REPO [OUTPUT]
```

Here `PKI_ARCH` refers to a PKI architecture defined in the configuration file, `CRL_REPO`
to the label of a CRL endpoint defined in the `services.crl-repo` section of said PKI
architecture, and `OUTPUT` is the (optional) name of the file to write the output to.
If not specified, data will be written to standard output.


| Flag | Argument | Use |
| ---- | -------- | --- |
|`--ignore-tty` | none | Never try to prevent binary data from being written to stdout, even if stdout appears to be a tty. |
|`--no-pem` | none | Do not PEM-armour the CRL, just output its raw DER encoding. |
|`--at-time` | ISO 8601 datetime | Generate the latest CRL at the point in time specified (default: now) |

Note: the `--at-time` flag takes the (simulated) publication schedule of the CRL into account.
For example, if the `n`th CRL was published on `2021-01-01`, the next one is scheduled for
`2021-01-31` and a certificate is revoked on `2021-01-02`, then telling Certomancer to generate
a CRL on `2021-01-03` will *not* cause the recently revoked certificate to be included.


# Generating OCSP responses

To generate an OCSP response from the CLI, use the `certomancer seance` subcommand.
Its general structure is

```
certomancer seance PKI_ARCH CERT_LABEL OCSP_RESPONDER
```

Here `PKI_ARCH` refers to a PKI architecture defined in the configuration file, `OCSP_RESPONDER`
to the label of an OCSP responder defined in the `services.ocsp` section of said PKI
architecture, and `CERT_LABEL` to the label of a certificate (or attribute certificate)
defined in the PKI architecture. An OCSP response that applies to that certificate will be
generated. Finally, `OUTPUT` specifies the (optional) name of the file to write the output to.
If not specified, data will be written to standard output.

| Flag | Argument | Use |
| ---- | -------- | --- |
|`--ignore-tty` | none | Never try to prevent binary data from being written to stdout, even if stdout appears to be a tty. |
|`--at-time` | ISO 8601 datetime | Generate the OCSP response at the point in time specified (default: now) |


# Writing data to PKCS#11 tokens

The `certomancer alch` command allows you to write data (including keys and certificates) to a PKCS#11 token.
Its general structure is

```
certomancer alch --cert CERT_LBL_1 --cert CERT_LBL_2 [OPTIONS...] PKI_ARCH
```

Generally, you'd pass one or more `--cert` arguments to write certificates (with their corresponding private keys)
to the token. On the token, the `CKA_LABEL` attribute for both certificate and key will be set to the value of the
certificate label in the Certomancer configuration. The `CKA_ID` attribute will be set similarly.


| Flag              | Argument | Use                                                                              |
|-------------------|----------|----------------------------------------------------------------------------------|
| `--module`        | string   | path to the PKCS#11 module library                                               |
| `--token-label`   | string   | name of the PKCS#11 token to use                                                 |
| `--slot-no`       | number   | slot number of the PKCS#11 token to use                                          |
| `--pin`           | pin      | PIN to access the token (if applicable)                                          |
| `--cert`          | string   | Add the certificate with the given label, and its private key (multiple allowed) |
| `--include-chain` | none     | Include certificates relevant to the chain of trust                              |

**WARNING:** The `alch` command is currently _not_ idempotent. Running it multiple times with the same input data is
inadvisable.
