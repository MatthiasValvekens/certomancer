# Certomancer plugin API


There are four types of plugin in Certomancer.

* **Extension plugins** &mdash; These are plugins that calculate & format values of certificate
  extensions (and other extension types in PKIX).
  See [default_plugins.py](../certomancer/default_plugins.py) for a few examples.
* **Attribute plugins** &mdash; These are plugins that calculate & format attributes for inclusion
  in X.509 attribute certificates, and are otherwise very similar to extension plugins.
* **Certificate profile plugins** &mdash; These are used to provision groups of extensions for
  (possibly multiple) certificates in a coherent, succinct way.
* **Service plugins** &mdash; These can be used define additional trust services that integrate
  with Certomancer in a way that is very similar to the "core" trust services that Certomancer
  supports (see [the section on service configuration](config.md#defining-service-endpoints)).
  You might want to take a look at [this module](../example_plugin/encrypt_echo.py) for a
  simple example service plugin.
  

In general, extension, attribute and certificate profile plugins in Certomancer must be
**stateless** (or at least, their API should be), and not assume that they will always be called
within the same PKI architecture. Service plugins should ideally follow the same rules.
Plugin instances are created when Certomancer starts, and will be used throughout the lifetime of
the application. See [further down](#registering-and-loading-plugins) for details on the loading
process.

Problems in plugin configuration should be signalled using the `ConfigurationError` exception class.

## Extension plugin API

Extension plugins inherit from `certomancer.ExtensionPlugin`.
Subclasses are expected to provide a (string) value for the `schema_label` attribute, which
will be used to identify the plugin within Certomancer.
If you expect your plugin to be used only with a certain kind of extensions (e.g. only certificate
extensions), you can set the `extension_type` attribute to the appropriate object identifier class.
This will allow you to do some introspection on the types of extensions that are passed in, but
usually that shouldn't be necessary.

The `provision` method must be implemented by all subclasses, and takes three parameters:

| Parameter | Type | Meaning |
| --- | --- | --- |
|`extn_id` | `ObjectIdentifier` or `None` | The `asn1crypto` object identifier of the extension for which a value is being generated. Can only be provided if `extension_type` is set to an appropriate subclass, and will be `None` otherwise.|
| `arch` | `PKIArchitecture` | The PKI architecture in which the plugin is being invoked. |
| `params` | depends | The parameters with which the plugin was invoked.|

An example:

```yaml
id: subject_alt_name
smart-value:
  schema: general-names
  params:
    - {type: email, value: test@example.com}
    - {type: directory-name, value: alice}
```

This will invoke the extension plugin with schema label `general-names`, and the content of `params`
as its parameters. Since the plugin needs to interact with the current PKI architecture to resolve
the entity name `alice`, a reference to the current PKI architecture will be passed via the `arch`
parameter. Since `general-names` is a generic plugin, its `extension_type` is `None`. Therefore,
Certomancer will not attempt to interpret the `subject_alt_name` reference before invoking the
plugin.


## Certificate profile API

Certificate profile plugins inherit from `certomancer.CertProfilePlugin`.
Subclasses are expected to provide a (string) value for the `profile_label` attribute, which
will be used to identify the profile plugin within Certomancer.

The `certomancer.CertProfilePlugin` base class defines two methods: `extensions_for_self` and
`extensions_for_issued`. Both are expected to return a list of `ExtensionSpec` objects.

The `extensions_for_self` method must be overridden by all subclasses, and determines
the extensions to put on the certificate on which the profile is declared.
On the other hand, the `extensions_for_issued` method is optional, and determines the
extensions to put on certificates issued under the one on which the profile is declared.
By default, it simply returns an empty list. It goes without saying that this method is
meaningless (and never called) for profiles that are used on attribute certificate definitions.

The parameters provided to these methods are as follows:

 - A reference to the active PKI architecture
 - The parameters provided to the profile (if any) at the place where it was declared.
 - The specification for the item to which the extensions will be applied.
 - (`extensions_for_issued` only) The specification for the issuer's certificate.

The following points are important to keep in mind when implementing new profiles:

 - It's possible for a given profile to be invoked twice to provide extensions for one and the same
   certificate, once through `extensions_for_self`, and once more through `extensions_for_issued`.
   This can happen e.g. when defining a CA hierarchy with multiple layers, all of which use the
   built-in `simple-ca` profile.
 - Since the item spec passed to the `CertProfilePlugin` includes the `profiles` dictionary
   for the item in question as part of its data, it's possible to inspect which other profiles
   will be applied. This allows for some form of cooperation between different profile plugins.
   Note that profiles are invoked in the order in which they are declared in the configuration,
   and that (generally) the last plugin to be invoked "wins" in case the same certificate extension
   is emitted more than once.


## Service plugin API

Service plugins inherit from `certomancer.ServicePlugin`, and have a slightly more involved API.
While Certomancer only exposes services over HTTP right now (and only via `POST`), service plugins
should not rely on any properties of the carrier protocol: the interface is simply
'bytes-in-bytes-out'. The simple `encrypt-echo` [example](../example_plugin/encrypt_echo.py)
should clarify what that means.


Subclasses of `ServicePlugin` are expected to provide a value for the `plugin_label` attribute.
Plugins can also override the `content_type` attribute to indicate what the content type of their
response is. Finally, there are two methods to implement: `process_plugin_config` and `invoke`.

A service definition using plugins in the configuration file looks like this:

```yaml
services:
  plugin:
    encrypt-echo:
      test-endpoint1:
        recipient: recipient1
      test-endpoint2:
        recipient: recipient2
```
Here, `encrypt-echo` is the plugin defined [here](../example_plugin/encrypt_echo.py).

The `process_plugin_config` method is called when Certomancer ingests the configuration file, once
for every endpoint registered for the plugin.
At this stage, the plugin cannot interact with any Certomancer APIs yet.
The only argument (`params`) to this method is the "raw" value of the configuration for the
endpoint, straight from the YAML parser. In the above example, that would be
`{'recipient': 'recipient1'}` for `test-endpoint1`, and `{'recipient': 'recipient2'}` for
`test-endpoint2`.
The `process_plugin_config` can return a more convenient representation of this configuration (e.g.
in a dataclass) for later use. The value returned will be stored in the `params` attribute of
the `PluginServiceInfo` object for that service.

The `invoke` method takes four arguments, and returns the endpoint's response as raw bytes.
If the plugin overrides the `content_type` attribute, the bytes returned should be a valid value
of that media type.

| Parameter | Type | Meaning |
| --- | --- | --- |
| `arch` | `PKIArchitecture` | The PKI architecture in which the service is being invoked. | 
| `info` | `PluginServiceInfo` | Contains metadata & configuration about the current endpoint; see below. |
| `request` | `bytes` | Contains the raw request body being passed to the plugin. |
| `at_time` | `datetime` | If not `None`, the plugin should (attempt to) simulate being invoked at the given time. |

A `PluginServiceInfo` object models one endpoint associated with a given plugin.
Besides the configuration options stored in `params`, it also allows the plugin to retrieve the URL
for the endpoint being accessed, among other features.


### Example: `encrypt-echo`

This is all a bit abstract, but a closer look at the [example](../example_plugin/encrypt_echo.py) 
and the accompanying [config file](../tests/data/with-plugin.yml) should help with putting the
explanation in context.
An endpoint for the `encrypt-echo` plugin takes only a certificate label as configuration.
This certificate label indicates the recipient.
When a client POSTs to the endpoint, the response body is encrypted, and the envelope key is then
encrypted using the recipient's public key (retrieved from Certomancer).
The recipient's certificate (also provided by Certomancer) is then embedded into the
final `EnvelopedData` CMS structure. Finally, the DER representation of the resulting CMS object
is sent back to the client.

While the use case is obviously a bit contrived, it demonstrates how to integrate Certomancer
with a cryptographic protocol for testing/mocking purposes.

### What if I need to do something more complicated?

Certomancer's plugin system was designed to be easy to integrate with minimal configuration, which
necessarily makes it a bit simplistic. If you want to add more complicated web-based functionality
to Certomancer, you might want to wrap the Animator WSGI application directly.
Combining a strategy like this with a "no-op" implementation of the `ServicePlugin` interface,
you can even keep most of Certomancer's configuration management features, while still allowing you
to do whatever you want in the WSGI layer.

## Registering and loading plugins

For any type of plugin, there are two steps to take care of:

 * registering the plugin.
 * making sure the module containing the plugin registration gets executed;

The latter is accomplished by listing the relevant module under `plugin-modules` in the
configuration file (see [here](../tests/data/with-plugin.yml) for an example).
Actually registering the plugin is done using

* `certomancer.extension_plugin_registry.register()` for extension plugins;
* `certomancer.service_plugin_registry.register()` for service plugins.

There are essentially two different ways to pass a plugin to the `register()` function:

* Use the appropriate `register()` function as a class decorator. This requires the class to have
  a no-parameter `__init__` method.
* Instantiate the plugin class yourself (possibly with parameters), 
  and pass the result to `register()`.

In the former case, the plugin registry will immediately instantiate the plugin, and only one
instance will be used throughout the application's lifetime. In the latter case, the code becomes
slightly more verbose, but it does afford some extra flexibilities:

* It allows the plugins to have a nontrivial `__init__` method;
* It allows multiple instances of the same plugin class to coexist (provided that the `plugin_label`
  value is different).


Right now, there is no way to pass "global" configuration to a plugin from Certomancer's own config
file, so plugins that depend on complicated initialisation logic should do their own config
management.
