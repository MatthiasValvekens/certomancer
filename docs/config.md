# Certomancer configuration


## Location

By default, Certomancer looks for a file named `certomancer.yml` in the current working directory.
Alternative configuration files can be selected using the `--config` switch.

## General structure

When launched from the command line, Certomancer loads its configuration from a YAML file.
See [example.yml](../example.yml) for an example.
The typical structure of such a file looks more or less like the following.

```yaml
# prefix prepended to all generated URLs
external-url-prefix: "http://test.test"

# key set definitions go here
keysets: ...

# Optionally load plugins from external modules
plugin-modules: ["example_plugin.encrypt_echo"]

# The "meat" of the configuration is in the PKI architecture definitions
pki-architectures:
  # Define a PKI architecture labelled "testing-ca"
  testing-ca:
    # Name of the key set to use
    keyset: testing-ca
    # Entities and their names are registered here
    entities: ...
    # Certificate definitions go here
    certs: ...
    # Configure PKI service endpoints under "services".
    # These services can be either builtin (OCSP, CRL, TSA, certificate repository)
    # or provided by plugins.
    services: ...
```


## Key set configuration

In Certomancer, a key set is a collection of named keys or key pairs. Key sets are configured under
the top-level key `keysets` in the configuration file.
The default assumption is that the private and public key are both available, but if necessary
Certomancer can also issue certificates for keys for which only the public half is known.

It goes without saying that you should *never* use a testing tool like Certomancer with private keys
that are also used in a production environment.

Here is an example of a `keysets` dictionary defining two key sets named `key-set-a` and
`key-set-b`, respectively.
By default, all paths are interpreted relative to the directory in which the configuration file
is located, but this can be overridden using the `--key-root` command line parameter.
The `path-prefix` is inserted between the key root and the key's `path` argument.
In other words, if the configuration file is located in `/opt/certomancer` and `path-prefix` is
`keydir`, then declaring a key with `path` set to `ca.key.pem` will cause Certomancer to attempt to
read a key in `/opt/certomancer/keydir/ca.key.pem`.

```yaml
keysets:
  key-set-a:
    # prefix to prepend to key paths
    path-prefix: keydir
    keys:
      ca:
        path: ca.key.pem
        password: "abcdefg"
      alice:
        path: alice.key.pem
        password: "hunter2"
      bob:
        path: bob-pub.key.pem
        # indicates that only the public key is available
        public-only: true
  key-set-b:
    keys:
      carol:
        path: keydir/carol.key.pem
        password: "blah"
```

Right now, Certomancer assumes that all keys are pregenerated. While allowing keys generated
on-the-fly might become a feature at some point, there are a number of reasons why pregenerating
keys is preferable:

 - It makes it easier to use Certomancer in a deterministic way, i.e. to ensure that the same set of
   inputs produces the same outputs.
 - It reduces Certomancer's start-up time. Key generation is typically computationally expensive.
 - For testing setups, key reuse is usually not a significant concern, so you can generate a bunch
   of keys *once*, and forget about them later.

Certomancer supports RSA, DSA, ECDSA and EdDSA keys. All of these can be generated using `openssl`.
Regardless of the type of key used, Certomancer should be able to infer the appropriate signing
algorithm to use automatically.


## PKI architecture definitions

In typical cases, the vast majority of the configuration passed to Certomancer lives under the
`pki-architectures` top-level key in the YAML file.

```yaml
pki-architectures:
  testing-ca-1: ...
  testing-ca-2: ...
```

The design philosophy is that different PKI architectures do not interact with one another (at
least not within Certomancer), and all have their own namespace. Key sets can be shared between
PKI architectures, however, and Certomancer's Animator component (the built-in WSGI application)
can serve multiple PKI architectures simultaneously. This allows one Certomancer installation to
take care of multiple testing setups at once.

PKI architectures can also be defined in separate files, like so:

```yaml
pki-architectures:
   testing-ca-1: path-to-file.yml
   testing-ca-2: path-to-other-file.yml
```

This is a matter of personal preference; to Certomancer, specifying a file path here is equivalent
to pasting (and indenting) the contents of said file at that location in the configuration.


### Components of a PKI architecture in Certomancer

Broadly speaking, there are four components to a PKI architecture in Certomancer.

 - **Entities:** In Certomancer, an entity is essentially a directory name with a label attached
   to it.
 - **Keys:** Every PKI architecture has a fixed set of (labelled) keys assigned to it. In principle,
   there is no a priori mapping between keys and entities.
 - **Certificates:** PKI architectures define certificates issued by & to its entities. The subject
   and issuer key for each certificate are sourced from the PKI architecture's key set.
   Entities can have multiple certificates issued to them.
 - **Services:** PKI architectures can provide trust services as well. These services are 
   exposed over HTTP via the Animator. Out of the box, Certomancer provides implementations for
   OCSP responders, time stamping services CRL repositories and distribution points and certificate
   repositories. This functionality can be extended using the [plugin API](plugins.md).

The following example shows the general structure of a PKI architecture definition.

```yaml
pki-architectures:
   testing-ca:
      keyset: some-keyset-label
      entities:
         ca:
            country-name: BE
            organization-name: Testing Authority
            common-name: CA
         alice:
            country-name: BE
            organization-name: Testing Authority
            organizational-unit-name: Signers
            common-name: Alice
      certs: ...  # omitted
      services: ... # omitted
```

### Defining entities

As the above example shows, entities are defined under the `entities` key. An entity definition
takes the form `<label>: <name-dict>`, where `<label>` is the entity's label within the current PKI
architecture, and `<name-dict>` is a collection of key-value pairs that together determine the
entity's distinguished name. The keys in `<name-dict>` should normalise to values registered in the
`x509.NameType` class of `asn1crypto`. Alternatively, you may specify OIDs directly.
All name entries will be encoded using the ASN.1 `UTF8String` type.

If some of the name values are the same for all entities, you may specify the common ones through
the `entity-defaults` key. The following setup is equivalent to the example previously shown.

```yaml
pki-architectures:
   testing-ca:
      keyset: some-keyset-label
      entity-defaults:
         country-name: BE
         organization-name: Testing Authority
      entities:
         ca:
            common-name: CA
         alice:
            organizational-unit-name: Signers
            common-name: Alice
      certs: ...  # omitted
      services: ... # omitted
```

Currently, there is no support for multi-valued name entries (e.g. DNs with multiple
`organization-name` values).

### Defining certificates

In a Certomancer PKI architecture definition, certificates are listed under the `certs`
key. Similar to keys and entities, they are also defined as `<label>: <spec>` pairs.

```yaml
pki-architectures:
   testing-ca:
      keyset: some-keyset-label
      entities: ... # omitted
      certs:
         ca:
            subject: ca
            issuer: ca
            validity:
               valid-from: "2000-01-01T00:00:00+0000"
               valid-to: "2500-01-01T00:00:00+0000"
            extensions:
               # These aren't necessarily meaningful in a self-signed certificate,
               # but we include them anyway to demonstrate the syntax.
               - id: basic_constraints
                 critical: true
                 value:
                    ca: true
               - id: key_usage
                 critical: true
                 smart-value:
                    schema: key-usage
                    params: [digital_signature, key_cert_sign, crl_sign]
         alice:
            subject: alice
            issuer: ca
            validity:
               valid-from: "2020-01-01T00:00:00+0000"
               valid-to: "2050-01-01T00:00:00+0000"
            extensions:
               - id: key_usage
                 critical: true
                 smart-value:
                    schema: key-usage
                    params: [digital_signature, non_repudiation]
      services: ... # omitted
```

#### Basic certificate properties

Here is an overview of the keys that set basic certificate properties and their values.


| Key | Type | Meaning |
| --- | --- | --- |
| `subject` |Entity label| The label of the entity to which the certificate is issued. If unspecified, it defaults to the entity with the same label as the certificate (if one exists).|
| `subject-key` |Key label| The key label used to determine the subject's public key for the purposes of the current certificate. Defaults to the value of `subject` if unspecified. Note that this default only makes sense if there exists a key with the same label as the value of `subject`, since entities are not a priori bound to keys in Certomancer.|
| `issuer` |Entity label| The label of the entity issuing the certificate.|
| `authority-key` |Key label| The label of the key that will be used to sign the certificate. Defaults to the value of `issuer`; the same caveats as those for `subject-key` also apply here.|
| `validity` |dictionary| Takes a dictionary with two keys, `valid-from` and `valid-to`. The values of these should be timestamps specified in ISO 8601 format (including UTC offset).|
| `serial` |integer| You can manually specify the certificate's serial number if you want. If unspecified, Certomancer will populate this field automatically, making sure that all certificates issued by a given issuer have distinct serial numbers.|
| `issuer-cert` |Cert label| You can optionally specify the "preferred" issuer's certificate to use when required by Certomancer's trust services. In principle, this isn't relevant for the certificate signing process itself, but having a preferred issuer certificate lying around is sometimes convenient for a variety of reasons. If the issuing entity has exactly one certificate issued to it, you don't need to worry about this setting.|


#### Certificate extensions

Many features of certificates (including some relatively basic ones) are provided by certificate
extensions. With the exception of the `subjectKeyIdentifier` and `authorityKeyIdentifier`
extensions, Certomancer requires all extensions to be declared in the configuration.
There are a number of ways to do so.

 - Explicitly declare extensions under the `extensions` key in a certificate definition 
   (see earlier example). The value of this key is an array, with each
   array entry defining another certificate extension and its value.
 - Extensions can also be inherited from other certificates through templating 
   (see [the section on templates](#using-certificate-definitions-as-templates)).
 - For a less verbose and "boilerplate-y" way of setting up extensions, have a look at 
   [the section on profiles](#certificate-profiles).

Entries in the `extensions` array are themselves dictionaries with the following keys:


| Key | Type | Meaning |
| --- | --- | --- |
| `id` |string| Mandatory; given by an OID string, or the name of a certificate extension known to `asn1crypto` (see `x509.ExtensionId`).|
| `critical` |boolean| Indicates whether the extension is critical or not.|
| `value` |depends| Direct specification of the extension's value, to be fed directly to the `asn1crypto` class that implements the extension.|
| `smart-value` |dictionary| Indicates that the value of the certificate extension is to be provided by an extension plugin (more details below).|

Using `value` isn't always feasible in practice: it only works for extensions that are supported in
`asn1crypto`, and YAML configuration doesn't always directly translate to input that
`asn1crypto` understands. Some certificate extensions will therefore require you to write your own
extension [plugin](plugins.md).
If neither `value` nor `smart-value` are defined, the extension value will be `NULL`.
  

To demonstrate a simple case where `smart-value` is used, consider the following declaration of
a `keyUsage` extension:

```yaml
id: key_usage
critical: true
smart-value:
   schema: key-usage
   params: [digital_signature, key_cert_sign, crl_sign]
```

The `schema` entry tells Certomancer to invoke the `key-usage` extension plugin, with the
parameters under `params` as input. The plugin will then compute a value for the certificate
extension.

For a more involved example, consider the following `subjectAltName` declaration:

```yaml
id: subject_alt_name
smart-value:
   schema: general-names
   params:
      - {type: email, value: test@example.com}
      - {type: directory-name, value: alice}
```

The `general-names` extension plugin can consume fairly complicated input, and also demonstrates
how extension plugins can interact with Certomancer in nontrivial ways. More specifically: the
implementation for `general-names` can look up entities when building values of type
`directory-name`.

Other extension plugins of this type include `aia-urls` and `crl-dist-url` &mdash; more about those
below.

Certomancer supplies a number of extension plugins natively, but you can
[define your own](plugins.md) as well.


#### Indicating revocation

Certomancer is also capable of simulating certificate revocation. This is accomplished through the
(optional) `revocation` entry in the certificate specification. See below for an example.

```yaml
pki-architectures:
   testing-ca:
      keyset: some-keyset-label
      entities: ... # omitted
      certs:
         ca: ... # omitted
         alice:
            subject: alice
            issuer: ca
            revocation:
               revoked-since: "2020-12-01T00:00:00+0000"
               reason: key_compromise
            validity:
               valid-from: "2020-01-01T00:00:00+0000"
               valid-to: "2050-01-01T00:00:00+0000"
            extensions:  ... # omitted
      services: ... # omitted
```

Additional CRL entry and/or OCSP extensions may be specified using the `crl-entry-extensions`
and `ocsp-response-extensions` keys. The syntax & plugin namespace for these are exactly the same
as for certificate extensions, and the CRL / OCSP response generator will pick up on them.

**Note:** The `crlReason` extension is populated automatically based on the `reason` key,
because the revocation reason is not usually treated like an extension in OCSP. Additionally,
make sure to use the `ocsp-response-extensions` and `crl-entry-extensions` for OCSP `SingleResponse`
extensions and `CRLEntry` extensions, respectively. OCSP `ResponseData` extensions and
`TBSCertificateList` extensions should be configured at the service level.


#### Using certificate definitions as templates

To avoid repeating large chunks of configuration, you can reuse prior certificate definitions
(within the same PKI architecture) as templates for newer ones. This will copy over all values
from the 'templated' certificate, and allow you to override and/or specify new values
in addition to those copied over.
Any extensions defined in the new certificate will be appended to the list of extensions of the
previous one.

There are a number of exceptions to take into account:

 * The `subject`, `subject-key` and `serial` entries will never be copied.
 * The `subjectAltName`, `subjectKeyIdentifier` and `authorityKeyIdentifier` extensions are excluded
   from being copied as well. For the latter two, this is implicit (since these extensions are
   populated under the hood, without taking configuration into account). On the other hand,
   `subjectAltName` is explicitly blacklisted, because otherwise there wouldn't be any mechanism to 
   redefine alternative subject names.
   
To derive a new certificate definition from an earlier one, use the `template` key.

```yaml
signer1:
   ...
signer2:
   subject: signer2
   template: signer1
   revocation:
      revoked-since: "2020-12-01T00:00:00+0000"
      reason: key_compromise
   extensions:
      - id: subject_alt_name
        smart-value:
           schema: general-names
           params:
              - {type: email, value: test2@example.com}
```

### Defining attribute certificates

Since version `0.7.0`, Certomancer also handles attribute certificates, as defined in X.509 and
RFC 5755.
Attribute certificates are defined under the `attr-certs` key in a PKI architecture, in much
the same way as regular certificates.

An example:

```yaml
example-attr-cert:
   holder:
      name: signer1
      cert: signer1
   issuer: aa
   issuer-cert: role-aa
   attributes:
      - id: role
        smart-value:
           schema: role-syntax
           params:
              name: {type: email, value: alice@example.com}
   validity:
      valid-from: "2010-01-01T00:00:00+0000"
      valid-to: "2030-01-01T00:00:00+0000"
   extensions:
      - id: no_rev_avail
```

Like regular certificates, attribute certificates have an issuer (the attribute authority, or AA).
In Certomancer configuration, the AA is an entity defined by the label in the `issuer` entry.
The issuer-related entries all have the same function as in a regular certificate config, with
the role of the CA replaced by the AA as the issuing authority.

Similarly, attribute certificates can also have extensions. The extension mechanism is the same
as for regular certificates. The configuration for revocation simulation and the certificate's
validity period also remains the same.

The two biggest differences are the following:

 - An attribute certificate doesn't have a _subject_, but a _holder_. In other words, it is assumed
   that the holder is already identified in some other way (usually by a regular public-key
   certificate issued by a CA). This conceptual difference is reflected in the encoding, and also
   in Certomancer's configuration.
 - As the name implies, attribute certificates assert that their holder has certain _attributes_,
   which of course have to be encoded in the certificate.

We discuss these in the next two sections.


#### Configuring the holder

The `holder` entry in an attribute certificate config dictionary contains entries that _define_
the holder and its key, and entries that define how it's encoded in an ASN.1 value.


| Key | Type | Meaning |
| --- | --- | --- |
| `name` | entity label | Label of the holding entity (required). |
| `cert` | cert label | Label of the holding entity's certificate (can be inferred if unique). |
| `key` | key label | Label of the holder's key. |
| `include_base_cert_id` | boolean | Include the `baseCertificateID` field in the holder value. Default `True`. |
| `include_entity_name` | boolean | Include the `entityName` field in the holder value. Default `False`. |
| `include_object_digest_info` | boolean | Include the `objectDigestInfo` field in the holder value. Default `False`. |
| `digested_object_type` | `cms.DigestedObjectType` value | Type of the object used in the `objectDigestInfo`, if present. Defaults to `public_key_cert`. |
| `obj_digest_algorithm` | string | Digest algorithm used in the `objectDigestInfo`, if present. Defaults to `sha256`. |

Note that RFC 5755 recommends sticking with one of `baseCertificateID`, `entityName` or
`objectDigestInfo`. Certomancer doesn't enforce this recommendation, but by default only
`baseCertificateID` is used.


#### Configuring attributes

Attribute definitions work very similarly to extensions, with some differences.


| Key | Type | Meaning |
| --- | --- | --- |
| `id` |string| Mandatory; given by an OID string, or the name of an attribute type known to `asn1crypto` (see `cms.AttCertAttributeType`).|
| `value` |depends| Direct specification of the extension's value, to be fed directly to the `asn1crypto` class that implements the attribute.|
| `smart-value` |dictionary| Indicates that the value of the certificate extension is to be provided by an attribute plugin (more details below). |
| `multivalued` |boolean| Indicates whether the `value` entry should be interpreted as a set instead of a single value. Defaults to `False`. |

Attribute plugins for use with `smart-value` can be defined by extending `AttributePlugin`
and registering the subclass in the relevant attribute plugin registry.
When `multivalued` is `True`, the plugin will be invoked once for every set of parameters.
The default set of `AttributePlugin` subclasses is listed further down.


### Certificate profiles

Since version `0.8.0`, Certomancer also offers a more parsimonious way to set up extensions for
a certificate and (if applicable) any other certificates issued under the certificate to which
the profile applies. This is easier to grasp with an example. Consider the following configuration
of four certificates.

```yaml
root:
   subject: root
   issuer: root
   validity:
      valid-from: "2000-01-01T00:00:00+0000"
      valid-to: "2500-01-01T00:00:00+0000"
   profiles:
      - id: simple-ca
        params:
           crl-repo: root
interm:
   issuer: root
   validity:
      valid-from: "2000-01-01T00:00:00+0000"
      valid-to: "2100-01-01T00:00:00+0000"
   profiles:
      - id: simple-ca
        params:
           max-path-len: 0
           crl-repo: interm
           ocsp-service: interm
interm-ocsp:
   issuer: interm
   validity:
      valid-from: "2000-01-01T00:00:00+0000"
      valid-to: "2100-01-01T00:00:00+0000"
   profiles:
      - ocsp-responder
signer:
   issuer: interm
   validity:
      valid-from: "2020-01-01T00:00:00+0000"
      valid-to: "2022-01-01T00:00:00+0000"
   profiles:
      - digsig-commitment
```

Let's break this down a little further:

 - The certificates `root` and `interm` include the `simple-ca` profile. As the name implies, this
   profile is intended for CA certificates, and it will ensure that the CA certificate declares a
   proper `basicConstraints` extension and has the correct key usage bits set. Moreover, it accepts
   additional `crl-repo` and `ocsp-service` parameters that can be used to automatically populate
   the `authorityAccessInformation` and `crlDistributionPoints` extensions on all certificates
   *issued by* those CAs.
 - The `interm-ocsp` certificate definition includes the `ocsp-responder` profile, which sets the
   correct extensions for OCSP issuance. Moreover, `simple-ca` is smart enough to skip setting
   revocation-related extensions on all "child" certificates that have the `ocsp-responder` profile.
 - Finally `digsig-commitment` is a very minimalistic profile that merely sets the
   `digitalSignature` and `nonRepudiation` (AKA `contentCommitment`) key usage bits. In this case
   the extensions it generates will be combined with those generated by the `simple-ca` profile
   used by its issuer.

Profiles are specified in the `profiles` field, as a list. For profiles without parameters,
it suffices to simply list the profile's name. If parameters are required, an `id` entry
with the profile name is required, and the parameters are to be supplied in an accompanying `params`
entry. The example above showcases both uses.

Profiles are useful for simple "happy path" testing, where the certificates don't really need
any special features. Note that profiles can be combined with the `extensions` field as well:
in that case, the extensions will simply be combined. If one of the definitions in `extensions`
has the same `id` as one of the extensions provided by a profile, then the former will be used
instead of the latter.

Certomancer supplies the following profiles natively:

 - `simple-ca` for CA certificates
 - `ocsp-responder` for delegated OCSP responder certificates
 - `digsig-commitment` for leaf certificates for digital signing with non-repudiation
   (this is basically a sample plugin)

The use of these profiles is demonstrated by the example further up in this section.
For more information on how to define your own profiles, have a look at
[the plugin API](plugins.md).


### Extension plugins available by default

#### Key usage

| **Schema label** | `key-usage` |
| --- | --- |
| **Params type** | list of strings |

As the name implies, the goal of this plugin is to set a value for the key usage (`id: key_usage`)
extension on a certificate. Strings in the list passed in `params` can be any of the following (see
`x509.KeyUsage` in `asn1crypto`):

* `digital_signature`
* `non_repudiation`
* `key_encipherment`
* `data_encipherment`
* `key_agreement`
* `key_cert_sign`
* `crl_sign`
* `encipher_only`
* `decipher_only`


**Example**
```yaml
- id: key_usage
  critical: true
  smart-value:
    schema: key-usage
    params: [digital_signature, key_cert_sign, crl_sign]
```


#### CRL distribution points

| **Schema label** | `crl-dist-url` |
| --- | --- |
| **Params type** | dictionary |

Used to populate the CRL distribution points extension (`id: crl_distribution_points`) with URLs
from a Certomancer certificate repository. The parameter dictionary (for now) only has one key,
`crl-repo-names`, which takes a list of `crl-repo` service labels as input. The download URLs 
of the referenced CRLs will be registered in the certificate extension.

**Example**
```yaml
- id: crl_distribution_points
  smart-value:
    schema: crl-dist-url
    params: {crl-repo-names: [root]}
```


Note: this example presumes the existence of a `crl-repo` service named `root`, which might have
been declared under `services` as follows (see further down for details):
```yaml
crl-repo:
  root:
    for-issuer: root
    signing-key: root
    simulated-update-schedule: "P90D"
```

#### Authority access information URLs

| **Schema label** | `aia-urls` |
| --- | --- |
| **Params type** | dictionary |

Plugin to set a value for the authority information access (AIA) extension
(`id:authority_information_access`). In particular, this is the standard way to indicate where to
find OCSP responders to check the status of a certificate. Certomancer currently supports two kinds
of authority access information: OCSP responder endpoints and `caIssuer` URLs. The function of the
latter is to point to one or more web locations where the issuer's certificate(s) can be downloaded,
in case the verifying party doesn't have access to it already.

To declare OCSP responder endpoints, pass a list of `ocsp` service labels as the value of the
`ocsp-responder-names` key in the `params` dictionary.
AIA entries of type `caIssuer` are populated from Certomancer's certificate repository services.
This is done by passing a list of dictionaries to the `ca-issuer-links` key in the `params`
dictionary. Each of these dictionaries can contribute one or more `caIssuer` URLs.
The keys in these dictionaries have the following meanings. 

| Key | Type | Meaning |
| --- | --- | --- |
| `repo` | Certificate repo label | Certificate repository to use. |
| `include-repo-authority` | boolean | Whether to include a link to the certificate of the repository's issuer. |
| `cert-labels` | list of certificate labels | Explicit list of certificates from the repo to include. |

The default value for `include-repo-authority` is `true`, and the default for `cert-labels` is the
empty list.


**Example**
```yaml
- id: authority_information_access
  smart-value:
    schema: aia-urls
    params:
      ocsp-responder-names: [interm-ocsp]
      ca-issuer-links:
        - repo: interm-repo
        - repo: root-repo
          include-repo-authority: false
          cert-labels: [interm]
```

Note: this example presumes that there is an OCSP responder service named `interm-ocsp` declared
in the `services` dictionary of the current PKI architecture, in addition to two certificate
repositories named `interm-repo` and `root-repo`. These might have been declared as follows
(see further down):

```yaml
services:
  ocsp:
    interm-ocsp:
      for-issuer: interm
      responder-cert: interm-ocsp
      signing-key: interm-ocsp
  cert-repo:
    root-repo:
      for-issuer: root
      publish-issued-certs: yes
    interm-repo:
      for-issuer: interm
      publish-issued-certs: no
```

#### GeneralNames plugin


| **Schema label** | `general-names` |
| --- | --- |
| **Params type** | list of dictionaries |

This plugin exists to provide values of type `GeneralNames`, and isn't tied to any particular
certificate extension, but was written with `subject_alt_name` in mind.
The dictionaries in the list passed to `params` each describe a `GeneralName` of a particular type.
The keys in these dictionaries have the following meanings.

| Key | Type | Meaning |
| --- | --- | --- |
| `type` | string | The type of the name, one of the values in `x509.GeneralName` in `asn`crypto` |
| `value` | depends | The actual name value, usually a string. |

For convenience, this plugin also defines a number of type aliases:
`uri` is mapped to `uniform_resource_identifier`, `email` is mapped to `rfc822_name` and
`ip` to `ip_address`. Hyphens and underscores are interchangeable here.

If the type is `directory_name`, then `value` can be interpreted in two ways:

* if `value` is a string, then the plugin will look for an entity with that label, and substitute
  that entity's name.
* if `value` is a dictionary, it is interpreted in the same way as an entity name definition.

**Example**

```yaml
- id: subject_alt_name
  smart-value:
    schema: general-names
    params:
      - {type: email, value: test@example.com}
      - {type: directory-name, value: signer1-alias}
      - {type: directory-name, value: {country-name: US, common-name: Bob}}
```

#### ISO timestamp plugin

| **Schema label** | `iso-time` |
| --- | --- |
| **Params type** | ISO 8601 timestamp string |

Simple plugin that parses ISO 8601 timestamp strings into `GeneralizedTime` objects. 

**Example**

```yaml
- id: invalidity_date
  smart-value:
    schema: iso-time
    params: "2020-11-30T00:00:00+0000"
```


#### Target information plugin

| **Schema label** | `ac-targets` |
| --- | --- |
| **Params type** | dictionary or list |

Helper to populate a targeting information extension, which is intended for use on attribute
certificates. It indicates the entity or entities to which the AC is targeted.
The parameters to `ac-targets` can be either a single target designation or a list of them.

In turn, a target designation can either be a string or a dictionary.

 - If the target designation is a string, it will be interpreted as an entity label.
   The resulting target value will be the corresponding entity's `directoryName`, used in a
   `targetName`-based `Target` value.
 - If the target designation is a dictionary, its `type` and `value` entries will be interpreted
   as in a general name dictionary (see `general-names`). In addition to those, the plugin looks
   for an `is-group` boolean entry to decide whether to tag the `Target` value as
   `targetName` or as `targetGroup`.


### Attribute plugins available by default

#### Role syntax plugin

| **Schema label** | `role-syntax` |
| --- | --- |
| **Params type** | dictionary |

Plugin that represents roles. The parameter dictionary must contain a `name` key identifying the
role's name as a `GeneralName` (see `general-names` extension plugin) and can optionally contain
an `authority` field, which is a list of `GeneralName` configs.

**Example**

```yaml
- id: role
  multivalued: true
  smart-value:
     schema: role-syntax
     params:
        - name: {type: email, value: alice@example.com}
        - name: {type: email, value: alice2@example.com}
```


#### IETF attribute syntax plugin

| **Schema label** | `ietf-attribute` |
| --- | --- |
| **Params type** | dictionary or list |

Plugin that implements the `IetfAttrSyntax` ASN.1 type that is used for a number of attribute types
in RFC 5755. Its parameters can be supplied as a dictionary or a list. If a dictionary is used,
the supported keys are `values` and `authority`. The latter is optional. If the parameters are
supplied as a list, its members will be interpreted as if they were given as arguments for the
`values` key.

The value of the `authority` key is interpreted as in the `general-names` plugin, if present.
The constituent values in `values` are, in general, dictionaries with a `type` and `value` key.
The possible `type`s and their usage are listed below.

| **`type` entry** | **Possible `value`s** | **Description** |
| --- | --- | --- |
| `string` | any string | a text string attribute value |
| `oid` | any dotted OID string | an object identifier attribute value |
| `octets` | any hexadecimal string | a binary (`OCTET STRING`) attribute value |

A constituent value can also be defined as a bare string (instead of a dictionary with `type` and 
`value` entries). In this case, the `type` is assumed to be `string`.


**Examples**

```yaml
- id: group
  smart-value:
     schema: ietf-attribute
     params:  # Here, we use the abbreviated form where the values are passed in as a list
        - type: string
          value: "Big Corp Inc. Employees"
        - "Team FooBar"  # this is equivalent to {type: string, value: "Team FooBar"}
        - type: octets
          value: deadbeef  # interpreted as a hex string
        - type: oid
          value: "2.999"
```

Here is the same example with an added policy authority, defined using a single DNS name.
Note that we have to use the dictionary form of the parameters now.

```yaml
- id: group
  smart-value:
     schema: ietf-attribute
     params:
        authority:
           - type: dns_name
             value: admin.example.com
        values:
           - type: string
             value: "Big Corp Inc. Employees"
           - "Team FooBar"
           - type: octets
             value: deadbeef
           - type: oid
             value: "2.999"
```

### Defining service endpoints

Certomancer's native support for PKI services is perhaps its most powerful feature.
Under the `services` key of a PKI architecture definition, you can enumerate & configure the
services to be provided by that architecture. These will be exposed by the Certomancer Animator
WSGI application, but the endpoint URLs can also be fed back into the certificate generation process
(e.g. to embed a reference to a CRL distribution point or OCSP responder).

The typical structure of a service listing looks roughly like this:

```yaml
pki-architectures:
   testing-ca:
      keyset: ...  # omitted
      entities: ...  # omitted
      certs: ...  # omitted
      services:
         ocsp:
            interm-ocsp-endpoint:
               for-issuer: interm
               responder-cert: interm-ocsp
               signing-key: interm-ocsp
         crl-repo:
            root-crl-repo:
               for-issuer: root
               signing-key: root
               simulated-update-schedule: "P90D"
            interm-crl-repo:
               for-issuer: interm
               signing-key: interm
               simulated-update-schedule: "P30D"
         time-stamping:
            tsa-service:
               signing-key: tsa
               signing-cert: tsa
         plugin:
            some-plugin:
              endpoint1: ...
              endpoint2: ...
            some-other-plugin: ...
```

Built-in services (`ocsp`, `crl-repo`, `time-stamping`, `cert-repo`) are declared directly under
the `services` key. Services provided by [plugins](plugins.md) are nested one level deeper, under
`plugin`.
Nonetheless, the general structure of a service declaration is the same in both cases:

```yaml
<service-type>:
  <endpoint1-label>: <endpoint1-params>
  <endpoint2-label>: <endpoint2-params>
```

For a built-in service type, `<service-type>` is one of `ocsp`, `crl-repo`, `time-stamping` or 
`cert-repo`. If the service is provided by a plugin, `<service-type>` is set to the label of the
service plugin (`some-plugin` or `some-other-plugin` in the example from earlier).

A particular service type can have one or more endpoints, each with a unique URL associated to it.
This URL is determined by Certomancer, and cannot be configured.
Typically, such a URL takes the form `/<arch-label>/<service-type>/<endpoint-label>`.
For example, the OCSP responder in the above example would be assigned the URL 
`/testing-ca/ocsp/interm-ocsp-endpoint`. The value of the top-level `external-url-prefix` setting is
prepended to all generated URLs.

Additionally, endpoint namespaces between different service types do not overlap, so endpoint labels
may be reused for different services (e.g. if you have a CA named `root`, you might want to give
all its associated services the label `root`).

We briefly explain the most important parameters that each of the built-in service types can take.

#### CRL distribution points

These are defined under `crl-repo` in the `services` dictionary. The following configuration
settings are available.

| Key | Type | Meaning |
| --- | --- | --- |
| `for-issuer` |Entity label| Entity label indicating the issuing CA for which the CRLs are generated.|
| `signing-key` |Key label| Key label to indicate the key that will be used to sign the CRLs. Defaults to the value of `for-issuer`, if a key with the same label exists. |
| `issuer-cert` |Cert label| Issuer's certificate. If the issuer only has one certificate, you don't need to bother with this setting. |
| `extra-urls` |list of strings| Additional URLs to register with this CRL distribution point. These don't mean anything within Certomancer.|
| `simulated-update-schedule` | duration string | The (simulated) time between CRL updates. This should be specified as an ISO 8601-style duration string, e.g. `P30D` for a 30-day period. Month/year indicators are not allowed. This value affects the way CRL numbers are generated, and also how the `thisUpdate` / `nextUpdate` fields are populated. |
| `crl-extensions` | list of dictionaries| Extra CRL extensions to use. These also follow the same format as certificate extensions.|


#### OCSP responders  

These are defined under `ocsp` in the `services` dictionary. The following configuration
settings are available.


| Key | Type | Meaning |
| --- | --- | --- |
| `for-issuer` |Entity label| Entity label indicating the issuing CA for which the OCSP responses are generated.|
| `responder-cert` |Cert label| OCSP responder cert to use.|
| `signing-key` |Key label| Key label to indicate the key that will be used to sign the OCSP responses. <br>Defaults to the value of `responder-cert`, if a key with the same label exists.|
| `issuer-cert` |Cert label| Issuer's certificate. If the issuer only has one certificate, you don't need to bother with this setting.|
| `ocsp-extensions` |list of dictionaries| Extra OCSP `ResponseData` extensions to use.<br>These also follow the same format as certificate extensions.|


#### Time stamping services

These are defined under `time-stamping` in the `services` dictionary. The following configuration
settings are available.

| Key | Type | Meaning |
| --- | --- | --- |
| `signing-cert` |Cert label| TSA cert to use.|
| `signing-key` |Key label| Key label to indicate the key that will be used to sign the OCSP responses. <br>Defaults to the value of `signing-cert`, if a key with the same label exists.|


#### Certificate repositories

These are defined under `cert-repo` in the `services` dictionary. In Certomancer, a certificate
repository provides an URL at which the (technically, a) certificate of a particular CA can be
retrieved, and optionally also publishes certificates issued by that CA.
The following configuration settings are available.

| Key | Type | Meaning |
| --- | --- | --- |
| `for-issuer` |Entity label| The issuing authority for which the certificate(s) are hosted.|
| `issuer-cert` |Cert label| The issuer's certificate to host. Can usually be inferred automatically.|
| `publish-issued-certs` |boolean| Whether to publish issued certificates through this API. The default is ``true``.|
