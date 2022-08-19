import abc
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Type, Union

from asn1crypto import cms, core
from asn1crypto.core import ObjectIdentifier

from ..config_utils import (
    ConfigurableMixin,
    ConfigurationError,
    plugin_instantiate_util,
)
from ..services import CertomancerServiceError
from .common import CertomancerObjectNotFoundError, PluginLabel
from .svc_config.api import ServiceInfo

if TYPE_CHECKING:
    from .issued.cert import CertificateSpec
    from .issued.general import ExtensionSpec, IssuedItemSpec
    from .pki_arch import PKIArchitecture

logger = logging.getLogger(__name__)

__all__ = [
    'ExtensionPlugin',
    'AttributePlugin',
    'ServicePlugin',
    'CertProfilePlugin',
    'SmartValueSpec',
    'PluginServiceInfo',
    'ExtensionPluginRegistry',
    'AttributePluginRegistry',
    'ServicePluginRegistry',
    'PluginServiceRequestError',
    'CertProfilePluginRegistry',
    'process_config_with_smart_value',
    'extension_plugin_registry',
    'attr_plugin_registry',
    'service_plugin_registry',
    'cert_profile_plugin_registry',
]


class ExtensionPlugin(abc.ABC):
    """
    Interface that supplies values for all sorts of extensions, including but
    not limited to certificate extensions.

    The :attr:`schema_label` and :attr:`extension_type` attributes are used
    to figure out when and how to invoke the plugin in question.
    The :attr:`schema_label` uniquely identifies the plugin, and the
    :attr:`extension_type` attribute indicates the type of object identifiers
    handled by the plugin (e.g. :class:`.x509.ExtensionId` for certificate
    extensions).
    Plugins that handle "generic" configuration that is not bound to any
    particular class of extensions can leave this parameter set to ``None``.

    .. note::
        If the OID you intend to use is not known to ``asn1crypto``, you should
        register it in the ``_map`` attribute of the appropriate
        :class:`~.core.ObjectIdentifier` subclass, and register a binding
        in the ``_oid_specs`` attribute of the corresponding extension class.
        This needs to happen while your module is imported, since otherwise
        ``asn1crypto`` may not pick up on it in time.

    The :meth:`provision` method should produce a value of the ``asn1crypto``
    type mandated by the extension's object identifier.

    Plugins must be stateless.
    """

    schema_label: str
    extension_type: Optional[Type[ObjectIdentifier]] = None

    def provision(
        self,
        extn_id: Optional[ObjectIdentifier],
        arch: 'PKIArchitecture',
        params,
    ):
        """
        Produce a value for an extension identified by ``extn_id``.

        :param extn_id:
            The ID of an extension. Guaranteed to be a subclass of
            :attr:`extension_type` if the latter is not ``None``.
            Otherwise ``extn_id`` will be ``None``.
        :param arch:
            The current :class:`.PKIArchitecture` being operated on.
        :param params:
            A parameter object, lifted directly from the input configuration.
            Plugins are expected to handle any necessary type checking.
        :return:
            A value compatible with the targeted extension type.
        """
        raise NotImplementedError


@dataclass(frozen=True)
class SmartValueSpec(ConfigurableMixin):
    """Class holding configuration for a plugin-generated value."""

    schema: PluginLabel
    params: dict = field(default_factory=dict)


class ExtensionPluginRegistry:
    """
    Registry of extension plugin implementations.
    """

    def __init__(self):
        self._dict = {}

    def register(self, plugin: Union[ExtensionPlugin, Type[ExtensionPlugin]]):
        """
        Register a plugin object.

        As a convenience, you can also use this method as a class decorator
        on plugin classes. In this case latter case, the plugin class should
        have a no-arguments ``__init__`` method.

        :param plugin:
            A subclass of :class:`ExtensionPlugin`, or an instance of
            such a subclass.
        """
        orig_input = plugin

        plugin, cls = plugin_instantiate_util(plugin)

        schema_label = plugin.schema_label
        if not isinstance(schema_label, str):
            raise ConfigurationError(
                f"Plugin {cls.__name__} does not declare a string-type "
                f"'schema_label' attribute."
            )

        extension_type = plugin.extension_type
        if extension_type is not None and (
            not isinstance(extension_type, type)
            or not issubclass(extension_type, ObjectIdentifier)
        ):
            raise ConfigurationError(
                f"Plugin {cls.__name__} does not declare an "
                f"'extension_type' attribute that is a subclass of "
                f"ObjectIdentifier."
            )
        self._dict[PluginLabel(schema_label)] = plugin
        return orig_input

    def process_value(
        self, extn_id: str, arch: 'PKIArchitecture', spec: SmartValueSpec
    ):
        try:
            proc: ExtensionPlugin = self._dict[spec.schema]
        except KeyError as e:
            raise ConfigurationError(
                f"There is no registered plugin for the schema "
                f"'{spec.schema}'."
            ) from e

        extn_oid: Optional[ObjectIdentifier]
        if proc.extension_type is not None:
            extn_oid = proc.extension_type(extn_id)
        else:
            extn_oid = None
        provisioned_value = proc.provision(extn_oid, arch, spec.params)
        if isinstance(provisioned_value, core.Asn1Value) and not isinstance(
            provisioned_value, core.ParsableOctetString
        ):
            # this allows plugins to keep working with extensions for which
            # we don't have an OID
            provisioned_value = core.ParsableOctetString(
                provisioned_value.dump()
            )
        return provisioned_value


class AttributePlugin(abc.ABC):
    # FIXME give attribute plugins an API to determine how they want
    #  to handle multivalued attrs (repeated invocation or in bulk)
    schema_label: str

    def provision(
        self,
        attr_id: Optional[ObjectIdentifier],
        arch: 'PKIArchitecture',
        params,
    ):
        """
        Produce a value for an attribute identified by ``extn_id``.

        :param attr_id:
            The ID of an extension.
        :param arch:
            The current :class:`.PKIArchitecture` being operated on.
        :param params:
            A parameter object, lifted directly from the input configuration.
            Plugins are expected to handle any necessary type checking.
        :return:
            A value compatible with the targeted attribute type.
        """
        raise NotImplementedError


class AttributePluginRegistry:
    """
    Registry of attribute plugin implementations.
    """

    def __init__(self):
        self._dict = {}

    def register(self, plugin: Union[AttributePlugin, Type[AttributePlugin]]):
        """
        Register a plugin object.

        As a convenience, you can also use this method as a class decorator
        on plugin classes. In this case latter case, the plugin class should
        have a no-arguments ``__init__`` method.

        :param plugin:
            A subclass of :class:`AttributePlugin`, or an instance of
            such a subclass.
        """
        orig_input = plugin

        plugin, cls = plugin_instantiate_util(plugin)

        schema_label = plugin.schema_label
        if not isinstance(schema_label, str):
            raise ConfigurationError(
                f"Plugin {cls.__name__} does not declare a string-type "
                f"'schema_label' attribute."
            )

        self._dict[PluginLabel(schema_label)] = plugin
        return orig_input

    def process_value(
        self,
        attr_id: str,
        arch: 'PKIArchitecture',
        spec: SmartValueSpec,
        multivalued: bool,
    ):
        try:
            proc: AttributePlugin = self._dict[spec.schema]
        except KeyError as e:
            raise ConfigurationError(
                f"There is no registered plugin for the schema "
                f"'{spec.schema}'."
            ) from e
        if multivalued:
            if not isinstance(spec.params, list):
                raise ConfigurationError(
                    "Params for multivalued attribute must be a list."
                )
            values = [
                proc.provision(
                    cms.AttCertAttributeType(attr_id), arch, inst_params
                )
                for inst_params in spec.params
            ]
        else:
            provisioned_value = proc.provision(
                cms.AttCertAttributeType(attr_id), arch, spec.params
            )
            values = [provisioned_value]
        return values


def process_config_with_smart_value(config_dict, thing):
    """
    Internal method for processing extension and attribute configuration
    that can make use of the 'smart_value' idiom.

    Modifies 'config_dict' in-place.

    :param config_dict:
    :param thing:
    """
    try:
        attr_id = config_dict['id']
    except KeyError as e:
        raise ConfigurationError(
            f"'id' entry is mandatory for all {thing}s"
        ) from e

    sv_spec = config_dict.get('smart_value', None)
    value = config_dict.get('value', None)
    if sv_spec is not None and value is not None:
        raise ConfigurationError(
            f"Cannot specify both smart-value and value on a "
            f"{thing}. At least one {attr_id} {thing} does not "
            f"meet this criterion."
        )
    elif sv_spec is not None:
        config_dict['smart_value'] = SmartValueSpec.from_config(sv_spec)
    elif value is not None and isinstance(value, dict):
        # asn1crypto compatibility
        config_dict['value'] = {
            k.replace('-', '_'): v for k, v in value.items()
        }


@dataclass(frozen=True)
class PluginServiceInfo(ServiceInfo):
    """
    Configuration describing a service provided by a service plugin.
    """

    base_url = '/plugin'

    plugin_label: PluginLabel
    """
    Label of the service plugin.
    """

    plugin_config: Any
    """
    Plugin-specific configuration data, as interpreted by the plugin.
    """

    content_type: str = 'application/octet-stream'
    """
    The content type of the response returned by the plugin.
    """

    @property
    def internal_url(self) -> str:
        """
        Internal URL for the service, i.e. without the external URL prefix
        or the arch_label prefix
        """

        return f"{self.base_url}/{self.plugin_label}/{self.label}"


class PluginServiceRequestError(CertomancerServiceError):
    """
    Indicates a client error in a plugin.

    Will map to a 400 Bad Request in Animator.
    """

    def __init__(self, *args, user_msg='Bad request'):
        self.user_msg = user_msg
        super().__init__(*args)


class ServicePlugin(abc.ABC):
    """
    Interface to register simple custom PKI service endpoints that can be set up
    entirely from within Certomancer configuration files.

    Service plugins of this type integrate automatically with Animator and
    Illusionist, and are sufficiently abstract to be easily adaptable to
    other protocol integrations.
    There are a number of restrictions:

     - Plugins take requests and responses as byte streams, but the content type
       of the response can be specified.
     - The URL of the HTTP endpoints provided by Animator and Illusionist is
       fixed, and there is only one endpoint per plugin / service label
       combination.
     - When called over HTTP, plugins receive no request metadata at all, and
       are only reachable by POST requests.
       This is to keep things as protocol-agnostic as possible.

    .. note::
        This API was designed to support simple protocols that do not depend
        on the feature set of HTTP (or any carrier protocol for that matter).

        Plugin authors that require more advanced HTTP-specific features can of
        course always implement a no-op :meth:`invoke`, and wrap the Animator
        WSGI application to intercept requests as necessary.
    """

    plugin_label: str

    content_type: str = 'application/octet-stream'
    """
    Response content type.
    """

    def process_plugin_config(self, params):
        """
        Invoked during config initialisation; this method allows you to hook
        into that process and parse user-provided configuration if necessary.

        Note that you cannot interact with the PKI architecture model at this
        stage.

        :param params:
            Original plugin parameters from the service definition
            in the configuration file.
        """
        return params  # pragma: nocover

    def invoke(
        self,
        arch: 'PKIArchitecture',
        info: PluginServiceInfo,
        request: bytes,
        at_time: Optional[datetime] = None,
    ) -> bytes:
        """
        Invoke the plugin with the specified PKI architecture and service
        definition, and feed it data from a request.

        :param arch:
            PKI architecture context.
        :param info:
            Parsed service definition object.
        :param request:
            Request bytes.
        :param at_time:
            If not ``None``, the plugin should behave as if the current time
            is given by the provided :class:`.datetime` value.
        :return:
            Response bytes
        """
        raise NotImplementedError


class ServicePluginRegistry:
    """
    Registry of service plugin implementations.
    """

    def __init__(self):
        self._dict = {}

    def register(self, plugin: Union[ServicePlugin, Type[ServicePlugin]]):
        """
        Register a service plugin object.

        As a convenience, you can also use this method as a class decorator
        on plugin classes. In this case latter case, the plugin class should
        have a no-arguments ``__init__`` method.

        :param plugin:
            A subclass of :class:`ServicePlugin`, or an instance of
            such a subclass.
        """

        orig_input = plugin
        plugin, cls = plugin_instantiate_util(plugin)
        plugin_label = plugin.plugin_label
        if not isinstance(plugin_label, str):
            raise ConfigurationError(
                f"Plugin {cls.__name__} does not declare a string-type "
                f"'plugin_label' attribute."
            )
        self._dict[PluginLabel(plugin_label)] = plugin
        return orig_input

    def invoke_plugin(
        self,
        arch: 'PKIArchitecture',
        info: PluginServiceInfo,
        request: bytes,
        at_time: Optional[datetime] = None,
    ) -> bytes:
        try:
            plugin: ServicePlugin = self._dict[info.plugin_label]
        except KeyError as e:
            raise ConfigurationError(
                f"There is no registered service plugin with label "
                f"'{info.plugin_label}'."
            ) from e
        return plugin.invoke(arch, info, request, at_time=at_time)

    def __getitem__(self, item: PluginLabel) -> ServicePlugin:
        try:
            return self._dict[item]
        except KeyError as e:
            raise CertomancerObjectNotFoundError(
                f"There is no plugin labelled '{item}'."
            ) from e

    def __contains__(self, item: PluginLabel):
        return item in self._dict

    def assert_registered(self, item: PluginLabel):
        if item not in self:
            raise ConfigurationError(f"Plugin '{item}' is not registered.")


class CertProfilePlugin(abc.ABC):
    """
    The base class for certificate profile plugins.

    Certificate profile plugins can be used to easily initialise groups
    of extensions, both on the certificates to which they apply, and optionally
    on the items issued under said certificates' authority.
    """

    profile_label: str
    """
    The internal identifier of the certificate profile. Must be overridden
    by implementing subclasses.
    """

    def extensions_for_self(
        self,
        arch: 'PKIArchitecture',
        profile_params: Any,
        spec: 'IssuedItemSpec',
    ) -> List['ExtensionSpec']:
        """
        Loads extensions for a certificate specification that includes the
        current profile.

        :param arch:
            The relevant PKI architecture.
        :param profile_params:
            The parameters of the profile, as specified in the configuration, if
            any.
        :param spec:
            The specification of the item on which the profile is to be applied.
        :return:
            A list of extension specifications.
        """
        raise NotImplementedError

    def extensions_for_issued(
        self,
        arch: 'PKIArchitecture',
        profile_params: Any,
        issuer_spec: 'CertificateSpec',
        issued_spec: 'IssuedItemSpec',
    ) -> List['ExtensionSpec']:
        """
        Loads extensions for a certificate specification for which the
        issuer's certificate uses the current profile.

        By default, this is a no-op, returning an empty list.

        .. note::
            This can be used to auto-provision authority access information
            in all issued certificates, for example.

        :param arch:
            The relevant PKI architecture.
        :param profile_params:
            The parameters of the profile, as specified in the configuration, if
            any.
        :param issuer_spec:
            The certificate specification for the issuer.
        :param issued_spec:
            The certificate specification for the issued item.
        :return:
            A list of extension specifications.
        """
        return []


class CertProfilePluginRegistry:
    """
    Registry of certificate profile plugin implementations.
    """

    def __init__(self):
        self._dict = {}

    def register(
        self, plugin: Union[CertProfilePlugin, Type[CertProfilePlugin]]
    ):
        """
        Register a plugin object.

        As a convenience, you can also use this method as a class decorator
        on plugin classes. In this case latter case, the plugin class should
        have a no-arguments ``__init__`` method.

        :param plugin:
            A subclass of :class:`CertProfilePlugin`, or an instance of
            such a subclass.
        """

        orig_input = plugin

        plugin, cls = plugin_instantiate_util(plugin)

        profile_label = plugin.profile_label
        if not isinstance(profile_label, str):
            raise ConfigurationError(
                f"Profile plugin {cls.__name__} does not declare a string-type "
                f"'profile_label' attribute."
            )

        self._dict[PluginLabel(profile_label)] = plugin
        return orig_input

    def __getitem__(self, item: PluginLabel) -> CertProfilePlugin:
        try:
            return self._dict[item]
        except KeyError as e:
            raise CertomancerObjectNotFoundError(
                f"There is no profile labelled '{item}'."
            ) from e

    def __contains__(self, item: PluginLabel):
        return item in self._dict

    def apply_profiles(
        self, arch: 'PKIArchitecture', item_spec: 'IssuedItemSpec'
    ) -> Dict[str, 'ExtensionSpec']:
        """
        Collect extensions generated by profiles associated with an issued
        item specification.
        The extensions are collected both from the item's own profiles, and
        from the settings specified by its issuer's profiles, if a certificate
        specification for the issuer can be unambiguously determined.

        :param arch:
            The PKI architecture in which we operate.
        :param item_spec:
            The item specification to use.
        :return:
            A dictionary mapping extension IDs to extension specifications.
        """

        collected_extensions = {}
        self_profile_config = item_spec.profiles
        for profile, params in self_profile_config.items():
            extensions = self[profile].extensions_for_self(
                arch, params, item_spec
            )
            collected_extensions.update(
                {ext_spec.id: ext_spec for ext_spec in extensions}
            )

        try:
            issuer_cert_lbl = item_spec.resolve_issuer_cert(arch)
            issuer_spec = arch.get_cert_spec(issuer_cert_lbl)
        except CertomancerObjectNotFoundError:
            issuer_spec = None

        if issuer_spec is not None:
            issuer_profile_config = issuer_spec.profiles
            for profile, params in issuer_profile_config.items():
                extensions = self[profile].extensions_for_issued(
                    arch, params, issuer_spec, item_spec
                )
                collected_extensions.update(
                    {ext_spec.id: ext_spec for ext_spec in extensions}
                )
        return collected_extensions


extension_plugin_registry = ExtensionPluginRegistry()
"""
The default extension plugin registry.
"""


attr_plugin_registry = AttributePluginRegistry()
"""
The default attribute plugin registry.
"""

service_plugin_registry = ServicePluginRegistry()
"""
The default service plugin registry.
"""

cert_profile_plugin_registry = CertProfilePluginRegistry()
"""
The default certificate profile plugin registry.
"""
