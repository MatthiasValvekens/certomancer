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

Certomancer supports RSA, ECDSA and DSA keys. All of these can be generated using `openssl`.
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

 * `subject` &mdash; The label of the entity to which the certificate is issued.
   If unspecified, it defaults to the entity with the same label as the certificate
   (if one exists).
 * `subject-key` &mdash; The key label used to determine the subject's public key for
   the purposes of the current certificate. Defaults to the value of `subject` if unspecified.
   Note that this default only makes sense if there exists a key with the same label
   as the value of `subject`, since entities are not a priori bound to keys in Certomancer.
 * `issuer` &mdash; The label of the entity issuing the certificate.
 * `authority-key` &mdash; The label of the key that will be used to sign the certificate.
   Defaults to the value of `issuer`; the same caveats as those for `subject-key` also
   apply here.
 * `validity` &mdash; Takes a dictionary with two keys, `valid-from` and `valid-to`.
   The values of these should be timestamps specified in ISO 8601 format (including UTC offset).
 * `serial` &mdash; You can manually specify the certificate's serial number if you want.
   If unspecified, Certomancer will populate this field automatically, making sure that
   all certificates issued by a given issuer have distinct serial numbers.
 * `issuer-cert` &mdash; You can optionally specify the "preferred" issuer's certificate
   to use when required by Certomancer's trust services. In principle, this isn't relevant
   for the certificate signing process itself, but having a preferred issuer certificate lying 
   around is sometimes convenient for a variety of reasons. If the issuing entity has exactly 
   one certificate issued to it, you don't need to worry about this setting.


#### Certificate extensions

Many features of certificates (including some relatively basic ones) are provided by certificate
extensions. With the exception of the `subjectKeyIdentifier` and `authorityKeyIdentifier`
extensions, Certomancer requires all extensions to be explicitly declared under the `extensions`
key in a certificate definition (see earlier example). The value of this key is an array, with each
array entry defining another certificate extension and its value.
Entries in the `extensions` array are themselves dictionaries with the following keys:

* `id` &mdash; Mandatory; given by an OID string, or the name of a certificate extension known to
  `asn1crypto` (see `x509.ExtensionId`).
* `critical` &mdash; Indicates whether the extension is critical or not.
* `value` &mdash; Direct specification of the extension's value, to be fed directly to the
  `asn1crypto` class that implements the extension. This isn't always feasible in practice:
  it only works for extensions that are supported in `asn1crypto`, and YAML configuration doesn't
  always directly translate to input that `asn1crypto` understands.
* `smart-value` &mdash; Indicates that the value of the certificate extension is to be provided
  by an extension plugin (more details below).
  
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
in the section on service endpoints below.

Certomancer supplies a number of extension plugins natively, but you can
[define your own](plugins.md) as well.


#### Indicating revocation

*(Under construction)*


### Defining service endpoints

*(Under construction)*
