import abc
import copy
import enum
import hashlib
import importlib
import itertools
import logging
import os
import os.path
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Iterable, Tuple, Type, Union, Any, \
    ClassVar
from zipfile import ZipFile

import yaml
from asn1crypto.core import ObjectIdentifier
from dateutil.parser import parse as parse_dt
from asn1crypto import x509, core, pem, ocsp, crl, cms, keys
from dateutil.tz import tzlocal
from asn1crypto.keys import PrivateKeyInfo, PublicKeyInfo

from .config_utils import (
    ConfigurationError, check_config_keys, LabelString,
    ConfigurableMixin, parse_duration, key_dashes_to_underscores, get_and_apply,
    SearchDir, plugin_instantiate_util
)
from .crypto_utils import (
    pyca_cryptography_present,
    load_public_key, load_private_key,
    load_cert_from_pemder
)
from .services import CertomancerServiceError, generic_sign, CRLBuilder, \
    choose_signed_digest, SimpleOCSPResponder, TimeStamper, \
    RevocationInfoInterface, url_distribution_point


logger = logging.getLogger(__name__)


class KeyLabel(LabelString):
    """Label referring to a key or key pair"""
    pass


class CertLabel(LabelString):
    """Label referring to a certificate"""
    pass


class EntityLabel(LabelString):
    """
    Label referring to an entity (e.g. the subject or issuer of a certificate).
    Entities more or less correspond to distinguished names.
    """
    pass


class ServiceLabel(LabelString):
    """
    Label referring to a service (OCSP, CRL, time stamper, ...).
    A service is uniquely identified by its type and its label.
    """
    pass


class PluginLabel(LabelString):
    """
    Label referring to a plugin (and the corresponding schema).
    """
    pass


class ArchLabel(LabelString):
    """
    Label referring to a Certomancer PKI architecture.
    """
    pass


class CertomancerObjectNotFoundError(CertomancerServiceError):
    pass


@dataclass(frozen=True)
class AsymKey:
    """Class representing asymmetric key pairs."""

    public: PublicKeyInfo
    private: Optional[PrivateKeyInfo] = None

    @property
    def algorithm(self):
        """Key algorithm, as a string."""
        return self.public.algorithm


class KeyFromFile:
    """
    Key backed by data from a file.
    Can be public or private, DER or PEM encoded.
    If the file contains a public key, pass ``public_only=True``.

    .. warning::
        Private keys are decrypted on access and then stored in memory.
        This shouldn't matter since you aren't supposed to use Certomancer in
        production environments, but hey, you do you.
    """

    def __init__(self, name: KeyLabel, path: str, public_only: bool = False,
                 password=None):
        self.name = name
        self.path = path
        self.public_only = public_only
        self.password = password
        self._key: Optional[AsymKey] = None

    @classmethod
    def from_config(cls, name, config, lazy=False) -> 'KeyFromFile':
        check_config_keys(name, ('path', 'public-only', 'password'), config)
        try:
            path = config['path']
        except KeyError as e:
            raise ConfigurationError("Key entry does not specify path") from e

        public_only = bool(config.get('public-only', False))
        password = get_and_apply(config, 'password', lambda x: x.encode('utf8'))
        result = KeyFromFile(
            name, path, public_only=public_only, password=password
        )
        if not lazy:
            result._load()
        return result

    def _load(self):
        if self._key is None:
            with open(self.path, 'rb') as keyf:
                key_bytes = keyf.read()
            if self.public_only:
                public = load_public_key(key_bytes)
                private = None
            else:
                private, public = load_private_key(key_bytes, self.password)
            self._key = AsymKey(public=public, private=private)

    @property
    def public_key_info(self) -> PublicKeyInfo:
        self._load()
        return self._key.public

    @property
    def private_key_info(self) -> Optional[PrivateKeyInfo]:
        self._load()
        return self._key.private

    @property
    def key_pair(self) -> AsymKey:
        self._load()
        return self._key


class KeySet:
    """A labelled collection of keys."""

    def __init__(self, config, search_dir: SearchDir, lazy_load_keys=False):
        check_config_keys(
            'KeySet', ('path-prefix', 'keys', 'default-password'), config
        )
        try:
            keys = config['keys']
        except KeyError as e:
            raise ConfigurationError(
                "The 'keys' entry is mandatory in all key sets"
            ) from e
        path_prefix = config.get('path-prefix', '')
        path_prefix = search_dir.search_subdir(path_prefix)

        default_password = config.get('default-password', None)

        # apply path prefix to key configs
        def _proc(key_conf):
            key_conf = copy.deepcopy(key_conf)
            try:
                key_conf['path'] = path_prefix.resolve(key_conf['path'])
            except KeyError:
                pass
            if default_password is not None:
                key_conf.setdefault('password', default_password)
            return key_conf

        self._dict = {
            KeyLabel(k): KeyFromFile.from_config(
                KeyLabel(k), _proc(v), lazy=lazy_load_keys
            )
            for k, v in keys.items()
        }

    def __getitem__(self, name: KeyLabel) -> KeyFromFile:
        try:
            return self._dict[name]
        except KeyError as e:
            raise CertomancerObjectNotFoundError(
                f"There is no key labelled '{name}'."
            ) from e

    def get_asym_key(self, name: KeyLabel) -> AsymKey:
        return self[name].key_pair

    def get_public_key(self, name: KeyLabel) -> PublicKeyInfo:
        return self[name].public_key_info

    def get_private_key(self, name: KeyLabel) -> PrivateKeyInfo:
        pki = self[name].private_key_info
        if pki is None:
            raise ConfigurationError(
                f"Key '{name}' does not have an associated private key."
            )
        return pki


class KeySets:
    """A labelled collection of key sets."""

    def __init__(self, config, search_dir, lazy_load_keys=False):
        results = {}
        configs_seen = {}
        for k, cfg in config.items():
            cfg = copy.deepcopy(cfg)
            if 'template' in cfg:
                template_keyset = cfg.pop('template')
                try:
                    template_cfg = copy.deepcopy(configs_seen[template_keyset])
                except KeyError as e:
                    raise ConfigurationError(
                        f"Key set definition with label '{k}' "
                        f"refers to '{template_keyset}' as a template, but "
                        f"'{template_keyset}' hasn't been declared yet."
                    ) from e
                # merge 'keys' entries
                template_keys = template_cfg['keys']
                try:
                    extra_keys = cfg.pop('keys')
                    template_keys.update(extra_keys)
                except KeyError:
                    pass
                # clobber all other entries
                template_cfg.update(cfg)
                # replace cfg with the updated one
                cfg = template_cfg
            configs_seen[k] = cfg
            results[k] = KeySet(
                cfg, lazy_load_keys=lazy_load_keys, search_dir=search_dir
            )
        self._dict = results

    def __getitem__(self, name) -> KeySet:
        try:
            return self._dict[name]
        except KeyError as e:
            raise CertomancerObjectNotFoundError(
                f"There is no registered key set labelled '{name}'."
            ) from e


class EntityRegistry:
    """A registry of entities.

    Entities are internally identified by their labels, which can be converted
    to distinguished names via the ``__getitem__`` accessor on the entity
    registry to which they belong.
    """

    def __init__(self, config, defaults=None):
        defaults = {} if defaults is None else \
            key_dashes_to_underscores(defaults)

        def _prepare_name(ent_cfg):
            new_cfg = dict(defaults)
            new_cfg.update(key_dashes_to_underscores(ent_cfg))
            return x509.Name.build(new_cfg)

        self._dict = {
            EntityLabel(k): _prepare_name(v) for k, v in config.items()
        }

    def __getitem__(self, label: EntityLabel) -> x509.Name:
        try:
            return self._dict[label]
        except KeyError as e:
            raise CertomancerObjectNotFoundError(
                f"There is no registered entity labelled '{label}'."
            ) from e

    def get_name_hash(self, label: EntityLabel, hash_algo: str):
        """
        Compute the hash of an entity's distinguished name.

        :param label:
            The entity to look up.
        :param hash_algo:
            Name of a hash algorithm.
        :return:
        """
        # TODO cache these
        ent = self[label]
        return getattr(hashlib, hash_algo)(ent.dump()).digest()


@dataclass(frozen=True)
class Validity(ConfigurableMixin):
    """Validity period of a certificate."""

    valid_from: datetime
    """
    Start of validity period. To be specified as an ISO 8601 datetime string
    (with timezone offset) in the configuration.
    """

    valid_to: datetime
    """
    End of validity period. To be specified as an ISO 8601 datetime string
    (with timezone offset) in the configuration.
    """

    @classmethod
    def process_entries(cls, config_dict):
        super().process_entries(config_dict)
        try:
            valid_from_str = config_dict['valid_from']
            valid_to_str = config_dict['valid_to']
        except KeyError:
            return  # constructor will error later
        try:
            config_dict['valid_from'] = parse_dt(valid_from_str)
            config_dict['valid_to'] = parse_dt(valid_to_str)
        except ValueError as e:
            raise ConfigurationError(
                "Illegal date-time string in validity specification"
            ) from e

    @property
    def asn1(self) -> x509.Validity:
        return x509.Validity({
            'not_before': x509.Time(
                {'utc_time' if self.valid_from.year < 2050 else 'general_time': self.valid_from}
            ),
            'not_after': x509.Time(
                {'utc_time' if self.valid_to.year < 2050 else 'general_time': self.valid_to}
            ),
        })

    @property
    def att_asn1(self) -> cms.AttCertValidityPeriod:
        return cms.AttCertValidityPeriod({
            'not_before_time': core.GeneralizedTime(self.valid_from),
            'not_after_time': core.GeneralizedTime(self.valid_to),
        })


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

    schema_label: str = None
    extension_type: Type[ObjectIdentifier] = None

    def provision(self, extn_id: Optional[ObjectIdentifier],
                  arch: 'PKIArchitecture', params):
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
        if extension_type is not None and \
                (not isinstance(extension_type, type)
                 or not issubclass(extension_type, ObjectIdentifier)):
            raise ConfigurationError(
                f"Plugin {cls.__name__} does not declare an "
                f"'extension_type' attribute that is a subclass of "
                f"ObjectIdentifier."
            )
        self._dict[PluginLabel(schema_label)] = plugin
        return orig_input

    def process_value(self, extn_id: str,
                      arch: 'PKIArchitecture', spec: SmartValueSpec):
        try:
            proc: ExtensionPlugin = self._dict[spec.schema]
        except KeyError as e:
            raise ConfigurationError(
                f"There is no registered plugin for the schema "
                f"'{spec.schema}'."
            ) from e
        if proc.extension_type is not None:
            extn_id = proc.extension_type(extn_id)
        else:
            extn_id = None
        provisioned_value = proc.provision(extn_id, arch, spec.params)
        if isinstance(provisioned_value, core.Asn1Value) and \
                not isinstance(provisioned_value, core.ParsableOctetString):
            # this allows plugins to keep working with extensions for which
            # we don't have an OID
            provisioned_value = \
                core.ParsableOctetString(provisioned_value.dump())
        return provisioned_value


DEFAULT_EXT_PLUGIN_REGISTRY = extension_plugin_registry \
    = ExtensionPluginRegistry()
"""
The default extension plugin registry.
"""


class AttributePlugin(abc.ABC):
    # FIXME give attribute plugins an API to determine how they want
    #  to handle multivalued attrs (repeated invocation or in bulk)
    schema_label: str = None

    def provision(self, attr_id: Optional[ObjectIdentifier],
                  arch: 'PKIArchitecture', params):
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

    def process_value(self, attr_id: str,
                      arch: 'PKIArchitecture', spec: SmartValueSpec,
                      multivalued: bool):
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


DEFAULT_ATTR_PLUGIN_REGISTRY = attr_plugin_registry \
    = AttributePluginRegistry()
"""
The default attribute plugin registry.
"""

def _process_with_smart_value(config_dict, thing):
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
class ExtensionSpec(ConfigurableMixin):
    """Specifies the value of an extension."""

    id: str
    """ID of the extension, as a string (see :module:`asn1crypto.x509`)."""

    critical: bool = False
    """Indicates whether the extension is critical or not."""

    value: object = None
    """Provides the value of the extension, in a form that the ``asn1crypto``
    value class for the extension accepts."""

    smart_value: Optional[SmartValueSpec] = None
    """
    Provides instructions for the dynamic calculation of an extension value
    through a plugin. Must be omitted if :attr:`value` is present.
    """

    @classmethod
    def process_entries(cls, config_dict):
        _process_with_smart_value(config_dict, "certificate extension")
        super().process_entries(config_dict)

    def to_asn1(self, arch: 'PKIArchitecture', extension_class):
        value = self.value
        if value is None and self.smart_value is not None:
            value = arch.extn_plugin_registry.process_value(
                self.id, arch, self.smart_value
            )

        return extension_class({
            'extn_id': self.id, 'critical': self.critical, 'extn_value': value
        })


EXCLUDED_FROM_TEMPLATE = frozenset(
    {'subject', 'subject_key', 'serial', 'certificate_file'}
)
EXTNS_EXCLUDED_FROM_TEMPLATE = frozenset({'subject_alt_name'})


@dataclass(frozen=True)
class RevocationStatus(ConfigurableMixin):
    """
    Models the revocation status of a certificate.

    .. warning::
        Currently, "temporary" revocations (a.k.a. certificate holds) cannot be
        represented properly.
    """

    revoked_since: datetime
    """
    Time of revocation.
    """

    reason: crl.CRLReason = None
    """
    Revocation reason.
    """

    crl_entry_extensions: List[ExtensionSpec] = field(default_factory=list)
    """
    CRL entry extensions to add when adding this revocation information to
    a CRL.
    """

    ocsp_response_extensions: List[ExtensionSpec] = field(default_factory=list)
    """
    Response extensions to add when reporting this revocation information
    via OCSP.
    """

    @classmethod
    def process_entries(cls, config_dict):
        super().process_entries(config_dict)
        try:
            revoked_since = config_dict['revoked_since']
        except KeyError:
            return
        config_dict['revoked_since'] = parse_dt(revoked_since)

        try:
            reason_spec = config_dict['reason']
            config_dict['reason'] = crl.CRLReason(reason_spec)
        except KeyError:
            pass

        _parse_extension_settings(config_dict, 'crl_entry_extensions')
        _parse_extension_settings(config_dict, 'ocsp_response_extensions')

    def to_crl_entry_asn1(self, serial_number: int,
                          extensions: List[crl.CRLEntryExtension]) \
            -> crl.RevokedCertificate:
        return CRLBuilder.format_revoked_cert(
            serial_number, reason=self.reason,
            revocation_date=self.revoked_since,
            extensions=extensions
        )

    def to_ocsp_asn1(self) -> ocsp.CertStatus:
        return ocsp.CertStatus(
            name='revoked', value={
                'revocation_time': self.revoked_since,
                'revocation_reason': self.reason
            }
        )


@dataclass(frozen=True)
class IssuedItemSpec(ConfigurableMixin):
    """Specification of a generic issued item."""

    serial: int
    """Serial number"""

    issuer: EntityLabel
    """Certificate issuer"""

    authority_key: KeyLabel
    """Key of the authority issuing the certificate.
    Private key must be available. Defaults to the value of :attr:`issuer`."""

    validity: Validity
    """Validity period of the certificate."""

    signature_algo: Optional[str]
    """Signature algorithm designation. Certomancer will try to figure out
    something sensible if none is given."""

    issuer_cert: Optional[CertLabel]
    """
    Label of the issuer certificate to use. If the issuer only has one
    certificate, it is not necessary to provide a value for this field.

    The certificate is only used to make sure the authority key identifier
    in the generated certificate matches up with the issuer's subject key
    identifier. Certomancer calculates these by hashing the public key (as
    recommended by :rfc:`5280`, but in principle CAs can do whatever they want.
    """

    digest_algo: str
    """Digest algorithm to use in the signing process. Defaults to SHA-256."""

    revocation: Optional[RevocationStatus]
    """Revocation status of the certificate, if relevant."""

    @classmethod
    def process_entries(cls, config_dict):
        # we can't set these at the dataclass level because of dataclass
        # inheritance rules
        # (solvable in Python 3.10 by making all arguments keyword-only, but
        #  that's not an option right now)
        config_dict.setdefault('signature_algo', None)
        config_dict.setdefault('issuer_cert', None)
        config_dict.setdefault('revocation', None)
        config_dict.setdefault('digest_algo', 'sha256')

        try:
            val_spec = config_dict['validity']
            config_dict['validity'] = Validity.from_config(val_spec)
        except KeyError:
            pass

        revocation = config_dict.get('revocation', None)
        if revocation is not None:
            config_dict['revocation'] = RevocationStatus.from_config(revocation)

        super().process_entries(config_dict)

    def resolve_issuer_cert(self, arch: 'PKIArchitecture') -> CertLabel:
        return self.issuer_cert or arch.get_unique_cert_for_entity(self.issuer)


def _as_general_name(name: x509.Name) -> cms.GeneralName:
    # note for readability: the 'name' parameter below is part of the Choice
    # API in asn1crypto, and has nothing to do with the fact that we're dealing
    # with name objects here
    return x509.GeneralName(name='directory_name', value=name)


@dataclass(frozen=True)
class HolderSpec(ConfigurableMixin):
    """Describes the holder of an attribute certificate."""

    name: EntityLabel
    """The name of the holding entity."""

    cert: Optional[CertLabel] = None
    """
    The label of the entity certificate to use when encoding the holder, 
    if the entity has more than one certificate.
    """

    key: Optional[KeyLabel] = None
    """
    The label of the public key to use when encoding the holder, 
    if the entity has more than one certificate.
    """

    include_base_cert_id: bool = True
    """
    Include the ``baseCertificateID`` field in the holder value.
    This is recommended by RFC 5755 and the default.
    """

    include_entity_name: bool = False
    """
    Include the ``entityName`` field in the holder value.
    ``False`` by default.
    """

    include_object_digest_info: bool = False
    """
    Include the ``objectDigestInfo`` field in the holder value.
    ``False`` by default, and further controlled by :attr:`digested_object_type`
    and :attr:`obj_digest_algorithm`.
    """

    digested_object_type: cms.DigestedObjectType = \
        cms.DigestedObjectType('public_key_cert')
    """
    The type of data to digest when computing the ``objectDigestInfo``
    field (see :class:`cms.DigestedObjectType`).
    """

    obj_digest_algorithm: str = 'sha256'
    """
    Name of the digest algorithm to use when producing holder identifiers
    of type ``objectDigestInfo``. Defaults to SHA-256.
    """

    @classmethod
    def process_entries(cls, config_dict):
        try:
            dot_setting = config_dict['digested_object_type']
            if isinstance(dot_setting, (int, str)):
                config_dict['digested_object_type'] \
                    = cms.DigestedObjectType(dot_setting)
            elif not isinstance(dot_setting, cms.DigestedObjectType):
                raise ConfigurationError(
                    f"Digested object type setting type must be 'str' or 'int', "
                    f"not {type(dot_setting)}"
                )
        except KeyError:
            pass

    def to_asn1(self, arch: 'PKIArchitecture') -> cms.Holder:
        result = {}
        holder_cert_label = self.cert \
                            or arch.get_unique_cert_for_entity(self.name)
        holder_cert: x509.Certificate = arch.get_cert(holder_cert_label)
        if self.include_base_cert_id:
            result['base_certificate_id'] = {
                'issuer': [_as_general_name(holder_cert.issuer)],
                'serial': holder_cert.serial_number
            }
        if self.include_entity_name:
            result['entity_name'] = [_as_general_name(holder_cert.subject)]
        if self.include_object_digest_info:
            type_desc = self.digested_object_type.native
            data_to_digest: bytes
            if type_desc == 'public_key':
                pk_info: keys.PublicKeyInfo = holder_cert.public_key
                # RFC 5755 § 7.3 requires that the entire PublicKeyInfo be
                # hashed
                # (Warning: this is _not_ what pk_info.sha256 does in
                #  asn1crypto!)
                if pk_info.algorithm == 'dsa' and \
                        not pk_info['algorithm']['parameters'].native:
                    raise NotImplementedError(
                        "DSA parameter inheritance is not supported"
                    )
                data_to_digest = pk_info.dump()
            elif type_desc == 'public_key_cert':
                data_to_digest = holder_cert.dump()
            else:
                raise NotImplementedError(
                    "Only 'public_key' and 'public_key_cert' are implemented"
                )

            digest_f = getattr(hashlib, self.obj_digest_algorithm)
            obj_digest = digest_f(data_to_digest).digest()

            result['object_digest_info'] = {
                'digested_object_type': self.digested_object_type,
                'digest_algorithm': {'algorithm': self.obj_digest_algorithm},
                'object_digest': obj_digest
            }
        return cms.Holder(result)


@dataclass(frozen=True)
class AttrSpec(ConfigurableMixin):
    """Specifies the value of an attribute."""

    id: str
    """ID of the attribute, as a string (see :module:`asn1crypto.cms`)."""

    value: object = None
    """Provides the value of the attribute, in a form that the ``asn1crypto``
    value class for the attribute accepts."""

    multivalued: bool = False
    """
    If ``True``, the :attr:`value` field will be interpreted as a set of
    values instead of a singular one.
    """

    smart_value: Optional[SmartValueSpec] = None
    """
    Provides instructions for the dynamic calculation of an attribute value
    through a plugin. Must be omitted if :attr:`value` is present.
    """

    @classmethod
    def process_entries(cls, config_dict):
        _process_with_smart_value(config_dict, "attribute")
        super().process_entries(config_dict)

    def to_asn1(self, arch: 'PKIArchitecture'):
        value = self.value
        if value is None and self.smart_value is not None:
            values = arch.attr_plugin_registry.process_value(
                self.id, arch, self.smart_value, self.multivalued
            )
        else:
            values = value if self.multivalued else [value]

        return cms.AttCertAttribute({
            'type': cms.AttCertAttributeType(self.id), 'values': values
        })


@dataclass(frozen=True)
class AttributeCertificateSpec(IssuedItemSpec):
    """Attribute certificate specification."""

    label: CertLabel
    """Internal name of the attribute certificate spec."""

    holder: HolderSpec
    """Description of the holder."""

    attributes: List[AttrSpec]
    """List of certified attributes."""

    extensions: List[ExtensionSpec] = field(default_factory=list)
    """Extension settings for the attribute certificate."""

    @classmethod
    def process_entries(cls, config_dict):
        try:
            holder_raw = config_dict['holder']
        except KeyError:
            raise ConfigurationError(
                "Attribute certificates must specify a holder"
            )
        if isinstance(holder_raw, dict):
            config_dict['holder'] = HolderSpec.from_config(holder_raw)
        elif isinstance(holder_raw, str):
            config_dict['holder'] = HolderSpec(name=EntityLabel(holder_raw))
        else:
            raise ConfigurationError(
                f"'holder' entry must be a string or a dictionary, not "
                f"{type(holder_raw)}."
            )

        _parse_extension_settings(config_dict, 'extensions')
        ext_spec = config_dict.get('attributes', ())
        if not isinstance(ext_spec, (list, tuple)):
            raise ConfigurationError(
                "Applicable attributes must be specified as a list."
            )
        config_dict['attributes'] = [
            AttrSpec.from_config(sett) for sett in ext_spec
        ]
        super().process_entries(config_dict)


@dataclass(frozen=True)
class CertificateSpec(IssuedItemSpec):
    """Certificate specification."""

    label: CertLabel
    """Internal name of the certificate spec."""

    subject: EntityLabel
    """Certificate subject"""

    subject_key: KeyLabel
    """Subject's (public) key. Defaults to the value of :attr:`subject`."""

    templatable_config: dict
    """Configuration that can be reused by other certificate specs."""

    extensions: List[ExtensionSpec] = field(default_factory=list)
    """
    Extension settings for the certificate.
    
    .. note::
        The ``subjectKeyIdentifier`` and ``authorityKeyIdentifier`` extensions
        are supplied automatically, but any other extensions (including
        ``basicConstraints`` for CA certificates) need to be explicitly
        specified in the configuration.
    """

    certificate_file: Optional[str] = None
    """
    Path to a file with a pre-generated copy of the certificate in question,
    either in DER or in PEM format.
    
    When the certificate determined by this certificate spec is requested,
    the certificate in the file will be returned.
    
    .. warning::
        Certomancer will not attempt to process any information from the
        certificate file, beyond parsing it into an X.509 certificate structure.
        Internally, the certificate spec's entries are used instead.
        It is the config writer's responsibility to make sure that both match
        up.

    .. note::
        This option is unavailable when external configuration is disabled.
        Moreover, it is excluded from templates derived from this certificate
        spec.
    """

    @property
    def self_issued(self) -> bool:
        """
        Check whether the corresponding certificate is self-issued,
        i.e. whether the subject and issuer coincide.

        .. warning::
            Self-issued and self-signed are two related, but very different
            notions. Not all self-issued certificates are self-signed (e.g.
            CA key rollover can be implemented using self-issued certificates),
            and in principle self-signed certificates need not be self-issued
            either (although that usually makes little sense in practice).
        :return:
        """
        return self.subject == self.issuer

    @property
    def self_signed(self) -> bool:
        """
        Check whether the produced certificate is self-signed,
        i.e. whether the signer's (public) key is the same as the subject key.
        """
        return self.subject_key == self.authority_key

    @classmethod
    def process_entries(cls, config_dict):
        _parse_extension_settings(config_dict, 'extensions')

        super().process_entries(config_dict)

    @classmethod
    def extract_templatable_config(cls, config_dict):

        # Do this first for consistency, so we don't put processed values
        # into the template
        for k, v in config_dict.items():
            if k.replace('-', '_') in EXCLUDED_FROM_TEMPLATE:
                continue
            elif k == 'extensions':
                yield k, [
                    ext_dict for ext_dict in v
                    if ext_dict['id'] not in EXTNS_EXCLUDED_FROM_TEMPLATE
                ]
            else:
                yield k, v


def _process_cert_spec_settings(cert_spec_config, config_search_dir,
                                cert_cache):
    cert_specs: Dict[CertLabel, CertificateSpec] = {}
    cert_labels_by_issuer = defaultdict(list)
    cert_labels_by_subject = defaultdict(list)
    serial_by_issuer = defaultdict(lambda: DEFAULT_FIRST_SERIAL)
    for name, cert_config in cert_spec_config.items():
        name = CertLabel(name)
        cert_config = key_dashes_to_underscores(cert_config)
        template = cert_config.pop('template', None)
        if template is not None:
            # we want to merge extensions from the template
            extensions = cert_config.pop('extensions', [])
            try:
                template_spec: CertificateSpec = \
                    cert_specs[CertLabel(template)]
            except KeyError as e:
                raise ConfigurationError(
                    f"Cert spec '{name}' refers to '{template}' as a "
                    f"template, but '{template}' hasn't been declared yet."
                ) from e
            effective_cert_config = dict(template_spec.templatable_config)
            template_extensions = \
                effective_cert_config.get('extensions', [])
            effective_cert_config.update(cert_config)
            # add new extensions
            effective_cert_config['extensions'] \
                = extensions + template_extensions
        else:
            effective_cert_config = dict(cert_config)

        # derive templatable config before setting defaults
        effective_cert_config['templatable_config'] = dict(
            CertificateSpec.extract_templatable_config(effective_cert_config)
        )

        effective_cert_config['label'] = name.value
        effective_cert_config.setdefault('subject', name.value)
        effective_cert_config.setdefault(
            'subject_key', effective_cert_config['subject']
        )
        try:
            issuer = effective_cert_config['issuer']
        except KeyError as e:
            raise ConfigurationError(
                f"Certificate spec {name} does not specify an issuer."
            ) from e
        effective_cert_config.setdefault('authority_key', issuer)
        serial = serial_by_issuer[issuer]
        effective_cert_config.setdefault('serial', serial)
        serial_by_issuer[issuer] = serial + 1

        cert_specs[name] = spec = CertificateSpec.from_config(
            effective_cert_config
        )
        if spec.certificate_file is not None:
            if config_search_dir is None:
                raise ConfigurationError(
                    f"Failed to load pregenerated cert with name {name}"
                    f"from file; external configuration is disabled."
                )
            full_path = config_search_dir.resolve(spec.certificate_file)
            try:
                pregenerated = load_cert_from_pemder(full_path)
                cert_cache[name] = pregenerated
            except (IOError, ValueError) as e:
                raise ConfigurationError(
                    f"Failed to load pregenerated cert with name {name}"
                    f"from file {full_path}."
                ) from e
        cert_labels_by_issuer[spec.issuer].append(name)
        cert_labels_by_subject[spec.subject].append(name)

    return cert_specs, cert_labels_by_issuer, cert_labels_by_subject


def _process_ac_spec_config(ac_spec_config):
    ac_specs: Dict[CertLabel, AttributeCertificateSpec] = {}
    cert_labels_by_issuer = defaultdict(list)
    cert_labels_by_holder = defaultdict(list)
    serial_by_issuer = defaultdict(lambda: DEFAULT_FIRST_SERIAL)
    for name, ac_config in ac_spec_config.items():
        name = CertLabel(name)
        ac_config = key_dashes_to_underscores(ac_config)
        effective_cert_config = dict(ac_config)

        effective_cert_config['label'] = name.value
        try:
            issuer = effective_cert_config['issuer']
        except KeyError as e:
            raise ConfigurationError(
                f"AC spec {name} does not specify an issuer."
            ) from e
        effective_cert_config.setdefault('authority_key', issuer)
        serial = serial_by_issuer[issuer]
        effective_cert_config.setdefault('serial', serial)
        serial_by_issuer[issuer] = serial + 1

        ac_specs[name] = spec = AttributeCertificateSpec.from_config(
            effective_cert_config
        )
        cert_labels_by_issuer[spec.issuer].append(name)
        cert_labels_by_holder[spec.holder.name].append(name)

    return ac_specs, cert_labels_by_issuer, cert_labels_by_holder


DEFAULT_FIRST_SERIAL = 0x1000


class PKIArchitecture:
    """
    A collection of entities, keys, certificates and trust services, as
    modelled by Certomancer.
    """

    # These config keys will be merged when an architecture is templated
    MULTIVAL_CONFIG_KEYS = (
        'entities', 'certs', 'entity-defaults',
        'attr-certs'
    )
    CONFIG_KEYS = ('keyset', 'services', *MULTIVAL_CONFIG_KEYS)

    @classmethod
    def build_architecture(cls, arch_label: ArchLabel, cfg: dict,
                           key_sets: KeySets, external_url_prefix,
                           extension_plugins: ExtensionPluginRegistry = None,
                           service_plugins: 'ServicePluginRegistry' = None,
                           config_search_dir: Optional[SearchDir] = None,
                           cert_cache=None, ac_cache=None) -> 'PKIArchitecture':
        check_config_keys(arch_label, PKIArchitecture.CONFIG_KEYS, cfg)
        key_set_label = cfg.get('keyset', arch_label)
        try:
            key_set = key_sets[key_set_label]
        except KeyError as e:
            raise ConfigurationError(
                f"There is no registered key set with label {key_set_label}"
            ) from e

        try:
            entity_cfg = cfg['entities']
        except KeyError as e:
            raise ConfigurationError(
                "The 'entities' key is required in all PKI architecture "
                "specifications."
            ) from e
        try:
            cert_specs = cfg['certs']
        except KeyError as e:
            raise ConfigurationError(
                "The 'certs' key is required in all PKI architecture "
                "specifications."
            ) from e
        try:
            ac_specs = cfg['attr-certs']
        except KeyError:
            ac_specs = None
        entities = EntityRegistry(
            entity_cfg, cfg.get('entity-defaults', None)
        )
        services = cfg.get('services', {})
        return PKIArchitecture(
            arch_label, key_set=key_set, entities=entities,
            cert_spec_config=cert_specs, service_config=services,
            external_url_prefix=external_url_prefix,
            extension_plugins=extension_plugins,
            config_search_dir=config_search_dir,
            service_plugins=service_plugins,
            ac_spec_config=ac_specs,
            cert_cache=cert_cache, ac_cache=ac_cache,
        )

    @classmethod
    def build_architectures(cls, key_sets: KeySets, cfgs, external_url_prefix,
                            config_search_dir: Optional[SearchDir],
                            extension_plugins: ExtensionPluginRegistry = None,
                            service_plugins: 'ServicePluginRegistry' = None):
        arch_specs = {}
        for arch_label, cfg in cfgs.items():
            arch_label = ArchLabel(arch_label)
            # external config
            if isinstance(cfg, str):
                if config_search_dir is None:
                    raise ConfigurationError(
                        f"Could not load external PKI definition with label "
                        f"'{arch_label}'; external configuration is disabled."
                    )
                cfg_path = config_search_dir.resolve(path=cfg)
                with open(cfg_path, 'r') as external_conf:
                    cfg = yaml.safe_load(external_conf)
            elif isinstance(cfg, dict):
                # make sure we don't mess with input data passed in
                # by the caller
                cfg = copy.deepcopy(cfg)
            else:
                raise ConfigurationError(
                    f"Architecture definition must be either a string or a "
                    f"dictionary; config with label {arch_label} has type "
                    f"{type(cfg)}."
                )
            if 'template' in cfg:
                template_arch = cfg.pop('template')
                # retrieve template config
                try:
                    template_cfg = copy.deepcopy(arch_specs[template_arch])
                except KeyError as e:
                    raise ConfigurationError(
                        f"Architecture definition with label '{arch_label}' "
                        f"refers to '{template_arch}' as a template, but "
                        f"'{template_arch}' hasn't been declared yet."
                    ) from e

                # first, merge multivalue config keys
                for key in PKIArchitecture.MULTIVAL_CONFIG_KEYS:
                    try:
                        extra_values = cfg.pop(key)
                    except KeyError:
                        continue
                    try:
                        orig_values = template_cfg[key]
                    except KeyError:
                        template_cfg[key] = orig_values = {}
                    # update effective config with values to merge
                    orig_values.update(extra_values)

                # ...then merge services...
                extra_services = cfg.pop('services', {})
                try:
                    svc_dict = template_cfg['services']
                except KeyError:
                    template_cfg['services'] = svc_dict = {}
                for svc_type, extra_svc_defs in extra_services.items():
                    try:
                        orig_svc_defs = svc_dict[svc_type]
                    except KeyError:
                        svc_dict[svc_type] = orig_svc_defs = {}
                    orig_svc_defs.update(extra_svc_defs)

                # ...then clobber the rest (all the multivalued keys should have
                # been deleted by now)
                template_cfg.update(cfg)
                cfg = template_cfg
            # store the config for potential later template use
            arch_specs[arch_label] = cfg
            yield cls.build_architecture(
                arch_label=arch_label, cfg=cfg, key_sets=key_sets,
                external_url_prefix=external_url_prefix,
                extension_plugins=extension_plugins,
                config_search_dir=config_search_dir,
                service_plugins=service_plugins
            )

    def __init__(self, arch_label: ArchLabel,
                 key_set: KeySet, entities: EntityRegistry,
                 cert_spec_config, service_config, external_url_prefix,
                 ac_spec_config=None,
                 extension_plugins: ExtensionPluginRegistry = None,
                 attr_plugins: AttributePluginRegistry = None,
                 service_plugins: 'ServicePluginRegistry' = None,
                 config_search_dir: Optional[SearchDir] = None,
                 cert_cache=None, ac_cache=None):

        self.arch_label = arch_label
        self.key_set = key_set
        self.entities = entities

        self.extn_plugin_registry = \
            extension_plugins or DEFAULT_EXT_PLUGIN_REGISTRY
        self.attr_plugin_registry = \
            attr_plugins or DEFAULT_ATTR_PLUGIN_REGISTRY

        self.service_registry: ServiceRegistry = ServiceRegistry(
            self, external_url_prefix, service_config,
            plugins=service_plugins
        )

        # Parse certificate specs
        # This only processes the configuration, the actual signing etc.
        # happens on-demand
        cert_specs: Dict[CertLabel, CertificateSpec] = {}
        self._cert_specs = cert_specs

        cert_cache = cert_cache if cert_cache is not None else {}
        ac_cache = ac_cache if ac_cache is not None else {}
        self._cert_specs, cert_labels_by_issuer, cert_labels_by_subject = \
            _process_cert_spec_settings(
                cert_spec_config, config_search_dir, cert_cache
            )
        self._ac_specs, ac_labels_by_issuer, ac_labels_by_holder = \
            _process_ac_spec_config(ac_spec_config or {})
        self._cert_labels_by_issuer: Dict[EntityLabel, List[CertLabel]] \
            = cert_labels_by_issuer
        self._cert_labels_by_subject: Dict[EntityLabel, List[CertLabel]] \
            = cert_labels_by_subject
        self._ac_labels_by_issuer: Dict[EntityLabel, List[CertLabel]] \
            = ac_labels_by_issuer
        self._ac_labels_by_holder: Dict[EntityLabel, List[CertLabel]] \
            = ac_labels_by_holder
        self._cert_cache = cert_cache
        self._ac_cache = ac_cache

    def get_cert_spec(self, label: CertLabel) -> CertificateSpec:
        try:
            return self._cert_specs[label]
        except KeyError as e:
            raise CertomancerObjectNotFoundError(
                f"There is no registered certificate labelled '{label}'."
            ) from e

    def get_attr_cert_spec(self, label: CertLabel) -> AttributeCertificateSpec:
        try:
            return self._ac_specs[label]
        except KeyError as e:
            raise CertomancerObjectNotFoundError(
                f"There is no registered attribute certificate "
                f"labelled '{label}'."
            ) from e

    def find_cert_label(self, cid: ocsp.CertId,
                        issuer_label: Optional[EntityLabel] = None,
                        is_ac=False) -> CertLabel:
        by_iss_map = (
            self._ac_labels_by_issuer if is_ac else self._cert_labels_by_issuer
        )
        # FIXME this doesn't really scale
        serial = cid['serial_number'].native
        if issuer_label is None:
            entities = self.entities
            name_hash = cid['issuer_name_hash'].native
            hash_algo = cid['hash_algorithm']['algorithm'].native
            try:
                issuer_label = next(
                    lbl for lbl in by_iss_map.keys()
                    if entities.get_name_hash(lbl, hash_algo) == name_hash
                )
            except StopIteration as e:
                raise CertomancerServiceError(
                    f"Could not find a suitable issuer for CertID {cid.native}."
                ) from e

        specs = by_iss_map[issuer_label]

        def _lbl_to_serial(lbl: CertLabel):
            if is_ac:
                cert = self.get_attr_cert(lbl)
                return cert['ac_info']['serial_number'].native
            else:
                cert = self.get_cert(lbl)
                return cert.serial_number

        try:
            return next(
                lbl for lbl in specs
                if _lbl_to_serial(lbl) == serial
            )
        except StopIteration as e:
            raise CertomancerServiceError(
                f"No certificate issued by {issuer_label} with serial number "
                f"{serial}."
            ) from e

    def _load_all_certs(self):
        # We group the certs per issuer in folders
        spec: CertificateSpec
        for label, spec in self._cert_specs.items():
            cert = self.get_cert(label)
            # Coerce unevaluated parts of cert object structure
            # noinspection PyStatementEffect
            cert.native
        for label, spec in self._ac_specs.items():
            cert = self.get_attr_cert(label)
            # Coerce unevaluated parts of cert object structure
            # noinspection PyStatementEffect
            cert.native

    def enumerate_certs_by_issuer(self) \
            -> Iterable[Tuple[EntityLabel, Iterable[CertificateSpec]]]:
        for iss_label, issd_certs in self._cert_labels_by_issuer.items():
            yield iss_label, map(self.get_cert_spec, issd_certs)

    def enumerate_attr_certs_by_issuer(self) \
            -> Iterable[Tuple[EntityLabel, Iterable[AttributeCertificateSpec]]]:
        for iss_label, issd_certs in self._ac_labels_by_issuer.items():
            yield iss_label, map(self.get_attr_cert_spec, issd_certs)

    def enumerate_attr_certs_of_holder(self, holder_name: EntityLabel,
                                       issuer: Optional[EntityLabel] = None):
        # slow, but eh, it'll do
        if issuer is None:
            relevant = itertools.chain(*self._ac_labels_by_issuer.values())
        else:
            relevant = self._ac_labels_by_issuer[issuer]
        for ac_label in relevant:
            ac_spec = self.get_attr_cert_spec(ac_label)
            if ac_spec.holder.name == holder_name:
                yield ac_spec

    def get_chain(self, cert_label: CertLabel) -> Iterable[CertLabel]:
        # TODO support different chaining modes
        #  (e.g. until a cert in a certain list of roots, or until a cert
        #  owned by a particular entity)
        cur_cert = self.get_cert_spec(cert_label)
        while not cur_cert.self_signed:
            next_cert_lbl = cur_cert.resolve_issuer_cert(self)
            cur_cert = self.get_cert_spec(next_cert_lbl)
            yield cur_cert.label

    def package_pkcs12(self, cert_label: CertLabel,
                       key_label: KeyLabel = None,
                       certs_to_embed: Iterable[CertLabel] = None,
                       password: bytes = None):
        try:
            from cryptography.hazmat.primitives.serialization import (
                pkcs12, load_der_private_key, NoEncryption,
                BestAvailableEncryption
            )
            from cryptography import x509 as pyca_x509
        except ImportError as e:  # pragma: nocover
            raise CertomancerServiceError(
                "pyca/cryptography is required for PKCS#12 serialisation."
            ) from e

        cert_spec = self.get_cert_spec(cert_label)
        cert_der = self.get_cert(cert_label).dump()
        if key_label is None:
            key_label = cert_spec.subject_key
        if certs_to_embed is None:
            certs_to_embed = list(self.get_chain(cert_label))
        # We need to convert between asn1crypto objects and pyca/cryptography
        # objects here.
        key_der = self.key_set.get_private_key(key_label).dump()
        chain_der = (self.get_cert(c).dump() for c in certs_to_embed)

        # convert DER to pyca/cryptography internal objects
        cert = pyca_x509.load_der_x509_certificate(cert_der)
        key = load_der_private_key(key_der, password=None)
        chain = [pyca_x509.load_der_x509_certificate(c) for c in chain_der]

        if not password:
            encryption_alg = NoEncryption()
        else:
            encryption_alg = BestAvailableEncryption(password)

        return pkcs12.serialize_key_and_certificates(
            name=None, key=key, cert=cert, cas=chain,
            encryption_algorithm=encryption_alg
        )

    def is_subject_key_available(self, cert: CertLabel):
        key_label = self.get_cert_spec(cert).subject_key
        key_pair = self.key_set.get_asym_key(key_label)
        return key_pair.private is not None

    def _dump_certs(self, use_pem=True, flat=False, include_pkcs12=False,
                    pkcs12_pass=None):
        include_pkcs12 &= pyca_cryptography_present()
        # start writing only after we know that all certs have been built
        ext = '.cert.pem' if use_pem else '.crt'
        for iss_label, iss_certs in self._cert_labels_by_issuer.items():
            if not flat:
                yield iss_label.value, None
            for cert_label in iss_certs:
                cert = self.get_cert(cert_label)
                base_name = cert_label.value
                if not flat:
                    base_name = os.path.join(iss_label.value, base_name)
                name = base_name + ext
                data = cert.dump()
                if use_pem:
                    data = pem.armor('certificate', data)
                yield name, data

                if include_pkcs12 and self.is_subject_key_available(cert_label):
                    yield base_name + '.pfx', self.package_pkcs12(
                        cert_label, password=pkcs12_pass
                    )

    def _dump_attr_certs(self, use_pem=True, flat=False):
        # start writing only after we know that all certs have been built
        ext = '.attr.cert.pem' if use_pem else '.attr.crt'
        for iss_label, iss_certs in self._ac_labels_by_issuer.items():
            if not flat:
                yield iss_label.value, None
            for cert_label in iss_certs:
                cert = self.get_attr_cert(cert_label)
                base_name = cert_label.value
                if not flat:
                    base_name = os.path.join(iss_label.value, base_name)
                name = base_name + ext
                data = cert.dump()
                if use_pem:
                    data = pem.armor('attribute certificate', data)
                yield name, data

    def dump_certs(self, folder_path: str, use_pem=True, flat=False,
                   include_pkcs12=False, pkcs12_pass=None):
        os.makedirs(folder_path, exist_ok=True)
        self._load_all_certs()
        itr_certs = self._dump_certs(
            use_pem=use_pem, flat=flat, include_pkcs12=include_pkcs12,
            pkcs12_pass=pkcs12_pass
        )
        itr_att_certs = self._dump_attr_certs(use_pem=use_pem, flat=flat)
        for name, data in itertools.chain(itr_certs, itr_att_certs):
            path = os.path.join(folder_path, name)
            if data is None:  # folder
                os.makedirs(path, exist_ok=True)
            else:
                with open(path, 'wb') as f:
                    f.write(data)

    def zip_certs(self, output_buffer, use_pem=True, flat=False,
                  include_pkcs12=False, pkcs12_pass=None):
        zip_file = ZipFile(output_buffer, 'w')
        lbl = self.arch_label.value
        itr = self._dump_certs(
            use_pem=use_pem, flat=flat, include_pkcs12=include_pkcs12,
            pkcs12_pass=pkcs12_pass
        )
        for name, data in itr:
            if data is None:
                continue
            fname = os.path.join(lbl, name)
            zip_file.writestr(fname, data)
        zip_file.close()

    def get_attr_cert(self, label: CertLabel) -> cms.AttributeCertificateV2:
        try:
            return self._ac_cache[label]
        except KeyError:
            pass
        spec = self.get_attr_cert_spec(label)
        issuer_name = self.entities[spec.issuer]
        authority_key = self.key_set[spec.authority_key]
        signature_algo = spec.signature_algo
        digest_algo = spec.digest_algo
        signature_algo_obj = choose_signed_digest(
            digest_algo, authority_key.public_key_info,
            signature_algo
        )

        try:
            issuer_cert_lbl = spec.resolve_issuer_cert(self)
            issuer_cert = self.get_cert(issuer_cert_lbl)
            aki = issuer_cert.key_identifier_value
        except CertomancerServiceError:
            aki = authority_key.public_key_info.sha1
        aki_value = x509.AuthorityKeyIdentifier({'key_identifier': aki})
        aki_extension = x509.Extension({
            'extn_id': 'authority_key_identifier',
            'critical': False,
            'extn_value': aki_value
        })
        extensions = [aki_extension]
        # add extensions from config
        extensions.extend(
            ext_spec.to_asn1(self, x509.Extension)
            for ext_spec in spec.extensions
        )

        attributes = [attr.to_asn1(self) for attr in spec.attributes]
        tbs = cms.AttributeCertificateInfoV2({
            'version': 'v2',
            'holder': spec.holder.to_asn1(self),
            'issuer': cms.AttCertIssuer(
                name='v2_form',
                value=cms.V2Form(
                    {'issuer_name': [_as_general_name(issuer_name)]}
                )
            ),
            'signature': signature_algo_obj,
            'serial_number': spec.serial,
            'att_cert_validity_period': spec.validity.att_asn1,
            'attributes': attributes,
            'extensions': extensions
        })

        signature = generic_sign(
            private_key=authority_key.private_key_info,
            tbs_bytes=tbs.dump(), signature_algo=signature_algo_obj
        )

        cert = cms.AttributeCertificateV2({
            'ac_info': tbs,
            'signature_algorithm': signature_algo_obj,
            'signature': signature
        })

        self._cert_cache[label] = cert
        return cert

    def get_cert(self, label: CertLabel) -> x509.Certificate:
        try:
            return self._cert_cache[label]
        except KeyError:
            pass

        spec = self.get_cert_spec(label)
        subject_name = self.entities[spec.subject]
        subject_key = self.key_set[spec.subject_key]
        issuer_name = self.entities[spec.issuer]
        authority_key = self.key_set[spec.authority_key]

        signature_algo = spec.signature_algo
        digest_algo = spec.digest_algo
        signature_algo_obj = choose_signed_digest(
            digest_algo, authority_key.public_key_info,
            signature_algo
        )

        # SKI and AKI are required by RFC 5280 in (almost) all certificates
        # so we include them here
        # TODO check for potential duplication?
        ski = subject_key.public_key_info.sha1
        ski_extension = x509.Extension({
            'extn_id': 'key_identifier',
            'critical': False,
            'extn_value': core.OctetString(ski)
        })
        if spec.self_signed:
            aki = ski
        else:
            try:
                issuer_cert_lbl = spec.resolve_issuer_cert(self)
                if issuer_cert_lbl == label:
                    raise ConfigurationError(
                        f"Self-reference detected: issuer cert for {label} "
                        f"resolves to itself, but the certificate is not "
                        f"self-signed: Authority key: {spec.authority_key}; "
                        f"subject key: {spec.subject_key}."
                    )
                issuer_cert = self.get_cert(issuer_cert_lbl)
                aki = issuer_cert.key_identifier_value
            except CertomancerServiceError:
                # use SHA-1 hash of issuer's public key as the default
                # AKI value (which should be equivalent to the above, unless
                # the user loaded in certificates that weren't generated
                # by Certomancer)
                aki = authority_key.public_key_info.sha1
        aki_value = x509.AuthorityKeyIdentifier({'key_identifier': aki})
        aki_extension = x509.Extension({
            'extn_id': 'authority_key_identifier',
            'critical': False,
            'extn_value': aki_value
        })
        extensions = [ski_extension, aki_extension]
        # add extensions from config
        extensions.extend(
            ext_spec.to_asn1(self, x509.Extension)
            for ext_spec in spec.extensions
        )
        tbs = x509.TbsCertificate({
            'version': 'v3',
            'serial_number': spec.serial,
            'signature': signature_algo_obj,
            'issuer': issuer_name,
            'validity': spec.validity.asn1,
            'subject': subject_name,
            'subject_public_key_info': subject_key.public_key_info,
            'extensions': extensions
        })
        tbs_bytes = tbs.dump()
        signature = generic_sign(
            private_key=authority_key.private_key_info,
            tbs_bytes=tbs_bytes, signature_algo=signature_algo_obj
        )

        cert = x509.Certificate({
            'tbs_certificate': tbs,
            'signature_algorithm': signature_algo_obj,
            'signature_value': signature
        })

        self._cert_cache[label] = cert
        return cert

    def check_revocation_status(self, cert_label, at_time: datetime,
                                is_ac=False) -> Optional[RevocationStatus]:
        spec = (
            self.get_attr_cert_spec(cert_label) if is_ac
            else self.get_cert_spec(cert_label)
        )
        revo = spec.revocation
        if revo is not None and revo.revoked_since <= at_time:
            return revo
        else:
            return None

    def get_cert_labels_for_entity(self, entity_label: EntityLabel) \
            -> List[CertLabel]:
        return self._cert_labels_by_subject[entity_label]

    def get_unique_cert_for_entity(self, entity_label: EntityLabel) \
            -> CertLabel:
        labels = self.get_cert_labels_for_entity(entity_label)
        if len(labels) != 1:
            raise CertomancerServiceError(
                f"The certificate for the entity '{entity_label}' is unclear."
            )
        return labels[0]

    def _format_revo(self, serial: int, revo: RevocationStatus):
        exts = [
            ext.to_asn1(self, crl.CRLEntryExtension)
            for ext in revo.crl_entry_extensions
        ]
        return revo.to_crl_entry_asn1(serial, exts)

    def get_revoked_certs_at_time(self, issuer_label: EntityLabel,
                                  at_time: datetime):
        labels = self._cert_labels_by_issuer[issuer_label]
        for cert_label in labels:
            revo = self.check_revocation_status(cert_label, at_time=at_time)
            cert = self.get_cert(cert_label)
            if revo is not None:
                yield self._format_revo(cert.serial_number, revo)

    def get_revoked_attr_certs_at_time(self, issuer_label: EntityLabel,
                                       at_time: datetime):
        labels = self._ac_labels_by_issuer[issuer_label]
        for cert_label in labels:
            revo = self.check_revocation_status(
                cert_label, at_time=at_time, is_ac=True
            )
            cert = self.get_attr_cert(cert_label)
            if revo is not None:
                yield self._format_revo(
                    cert['ac_info']['serial_number'].native, revo
                )


@dataclass(frozen=True)
class ServiceInfo(ConfigurableMixin):
    """Base class to describe a PKI service."""

    arch_label: ArchLabel
    """Architecture to which the service belongs. """

    label: ServiceLabel
    """
    Label by which the service is referred to within Certomancer configuration.
    """

    external_url_prefix: str
    """
    Prefix that needs to be prepended to produce a "fully qualified" URL.
    """

    base_url: ClassVar[str]

    @property
    def internal_url(self) -> str:
        """
        Internal URL for the service, i.e. without the external URL prefix
        or the arch_label prefix
        """

        return f"{self.base_url}/{self.label}"

    @property
    def full_relative_url(self):
        """
        Full URL where the service's main endpoint can be found,
        relative to :attr:`external_url_prefix`.

        This is the URL used when listing service links in the web UI.
        """
        return f"{self.arch_label}{self.internal_url}"

    @property
    def url(self) -> str:
        """
        Full URL where the service's main endpoint can be found.

        This is the value that is embedded into certificates.
        """
        return f"{self.external_url_prefix}/{self.full_relative_url}"


@dataclass(frozen=True)
class OCSPResponderServiceInfo(ServiceInfo):
    """Configuration describing an OCSP responder."""

    base_url = '/ocsp'

    for_issuer: EntityLabel
    """
    Issuing entity on behalf of which the responder acts.
    """

    responder_cert: CertLabel
    """
    Responder's certificate to use.
    
    .. note::
        This certificate will be embedded in the response's certificate store,
        and the public key embedded inside will be used to derive the 
        ``responderId`` entry in the OCSP packet.
        
    """

    signing_key: Optional[KeyLabel] = None
    """
    Key to use to sign the OCSP response.
    
    Will be derived from ``responder_cert`` if not specified.
    
    .. note::
        This option exists only to allow invalid OCSP responses to be created.
    """

    signature_algo: Optional[str] = None
    """
    Signature algorithm to use. You can use this field to enforce RSASSA-PSS 
    padding, for example.
    """

    issuer_cert: Optional[CertLabel] = None
    """
    Issuer certificate. If the issuing entity has only one certificate, 
    you don't need to supply a value for this field.
    """

    digest_algo: str = 'sha256'
    """Digest algorithm to use in the signing process. Defaults to SHA-256."""

    ocsp_extensions: List[ExtensionSpec] = field(default_factory=list)
    """
    List of additional OCSP response extensions.
    
    Note: only extensions with a fixed value are allowed here, you cannot
    customise the value based on the request received.
    
    For this reason, the ``nonce`` extension is handled automatically by
    Certomancer.
    """

    is_aa_responder: bool = False
    """
    Flag indicating whether the OCSP responder queries attribute certificates
    or regular certificates.
    """

    @classmethod
    def process_entries(cls, config_dict):
        try:
            config_dict.setdefault('signing_key', config_dict['responder_cert'])
        except KeyError:
            pass

        _parse_extension_settings(config_dict, 'ocsp_extensions')

    def resolve_issuer_cert(self, arch: 'PKIArchitecture') -> CertLabel:
        return self.issuer_cert or \
               arch.get_unique_cert_for_entity(self.for_issuer)


@dataclass(frozen=True)
class TSAServiceInfo(ServiceInfo):
    """Configuration describing a time stamping service."""

    base_url = '/tsa'

    signing_cert: CertLabel
    """
    Label of the signer's certificate.
    """

    signing_key: Optional[KeyLabel] = None
    """
    Key to sign responses with. Ordinarily derived from :attr:`signing_cert`.
    """

    signature_algo: Optional[str] = None
    """
    Signature algorithm to use. You can use this field to enforce RSASSA-PSS 
    padding, for example.
    """

    digest_algo: str = 'sha256'
    """Digest algorithm to use in the signing process. Defaults to SHA-256."""

    certs_to_embed: List[CertLabel] = field(default_factory=list)
    """Extra certificates to embed."""

    @classmethod
    def process_entries(cls, config_dict):
        try:
            config_dict.setdefault('signing_key', config_dict['signing_cert'])
        except KeyError:
            pass


def _parse_extension_settings(sett_dict, sett_key):
    try:
        ext_spec = sett_dict.get(sett_key, ())
        if not isinstance(ext_spec, (list, tuple)):
            raise ConfigurationError(
                "Applicable extensions must be specified as a list."
            )
        sett_dict[sett_key] = result = [
            ExtensionSpec.from_config(sett) for sett in ext_spec
        ]
        return result
    except KeyError:
        return []


@enum.unique
class CRLType(enum.Enum):
    """
    Type of CRL. Determines flags in the issuing distribution point extension.

    Note: Certomancer internally does not distinguish between user certs and
    CA certs, so these will be treated uniformly.

    Note: RFC 5755 bans AAs from acting as CAs, so in principle AA-backed CRLs
    should not intersect with CA-backed ones in a well-managed PKI/PMI
    infrastructure (unless CRLs are delegated).
    However, Certomancer will still allow you to mix and match.
    """

    USER_ONLY = 'user-only'
    """
    Include only user certs.
    """

    CA_ONLY = 'ca-only'
    """
    Include only CA certs.
    """

    AC_ONLY = 'ac-only'
    """
    Include only attribute certs.
    """

    MIXED = 'mixed'
    """
    Unspecified.
    """
    # TODO mixed CRLs would be interesting for edge case testing
    #  but for that to work well we need to support generating indirect
    #  CRLs properly first (IDP extension management etc.)


@dataclass(frozen=True)
class CRLRepoServiceInfo(ServiceInfo):
    """
    Configuration describing a CRL repository/distribution points.

    The main purpose of this service is to model a distribution location
    that makes the "freshest" CRL available for download, but it can also
    serve CRL archives.

    .. note::
        There is currently no support for delta CRLs, but in principle
        indirect CRLs can be generated if you implement the relevant
        extensions yourself using plugins and the :attr:`crl_extensions`
        parameter.
    """

    base_url = '/crls'

    for_issuer: EntityLabel
    """
    Issuing entity for which the CRLs are issued.
    """

    signing_key: KeyLabel
    """
    Key to sign CRLs with.
    """

    simulated_update_schedule: timedelta
    """
    Time interval for (regular) CRL updates. Used to generate CRL numbers
    and to populate the ``thisUpdate`` and ``nextUpdate`` fields.
    
    The time origin is taken to be the start of the validity period of
    :attr:`issuer_cert`.
    """

    issuer_cert: Optional[CertLabel] = None
    """Issuer's certificate."""

    extra_urls: List[str] = field(default_factory=list)
    """
    Extra URLs to add to the distribution point.
    
    These don't have any function within Certomancer.
    """

    signature_algo: Optional[str] = None
    """
    Signature algorithm to use. You can use this field to enforce RSASSA-PSS 
    padding, for example.
    """

    digest_algo: str = 'sha256'
    """Digest algorithm to use in the signing process. Defaults to SHA-256."""

    crl_extensions: List[ExtensionSpec] = field(default_factory=list)
    """
    List of additional CRL extensions.
    """

    crl_type: CRLType = CRLType.MIXED
    """
    Type of CRL.
    """

    @classmethod
    def process_entries(cls, config_dict):
        try:
            upd_sched = config_dict['simulated_update_schedule']
            config_dict['simulated_update_schedule'] = parse_duration(upd_sched)
        except KeyError:
            pass
        try:
            config_dict.setdefault('signing_key', config_dict['for_issuer'])
        except KeyError:
            pass
        try:
            config_dict['crl_type'] = CRLType(config_dict['crl_type'])
        except KeyError:
            pass

        _parse_extension_settings(config_dict, 'crl_extensions')

    @property
    def latest_external_url(self):
        return f"{self.url}/latest.crl"

    @property
    def latest_full_relative_url(self):
        return f"{self.full_relative_url}/latest.crl"

    def archive_url(self, for_crl_number):
        return f"{self.internal_url}/archive-{for_crl_number}.crl"

    def format_distpoint(self):
        return url_distribution_point(
            self.latest_external_url, self.extra_urls
        )

    def format_idp(self):
        result = url_distribution_point(
            self.latest_external_url, self.extra_urls
        )
        if self.crl_type == CRLType.AC_ONLY:
            result['only_contains_attribute_certs'] = True
        elif self.crl_type == CRLType.CA_ONLY:
            result['only_contains_ca_certs'] = True
        elif self.crl_type == CRLType.USER_ONLY:
            result['only_contains_user_certs'] = True
        return result

    def resolve_issuer_cert(self, arch: 'PKIArchitecture') -> CertLabel:
        return self.issuer_cert or \
               arch.get_unique_cert_for_entity(self.for_issuer)


@dataclass(frozen=True)
class BaseCertRepoServiceInfo(ServiceInfo):
    for_issuer: EntityLabel
    issuer_cert: Optional[CertLabel] = None


@dataclass(frozen=True)
class CertRepoServiceInfo(BaseCertRepoServiceInfo):
    base_url = '/certs'
    publish_issued_certs: bool = True

    @staticmethod
    def issuer_cert_file_name(use_pem=True):
        fname = f"ca.{'cert.pem' if use_pem else 'crt'}"
        return f"{fname}"

    def issued_cert_url_path(self, label: CertLabel, use_pem=True):
        if not self.publish_issued_certs:
            raise ConfigurationError(
                f"Cert repo '{self.label}' does not make issued certs public"
            )
        fname = f"{label}.{'cert.pem' if use_pem else 'crt'}"
        return f"issued/{fname}"

    def issuer_cert_url(self, use_pem=True):
        fname = CertRepoServiceInfo.issuer_cert_file_name(use_pem=use_pem)
        return f"{self.url}/{fname}"

    @property
    def issuer_cert_external_url(self):
        fname = CertRepoServiceInfo.issuer_cert_file_name(use_pem=True)
        return f"{self.url}/{fname}"

    @property
    def issuer_cert_full_relative_url(self):
        fname = CertRepoServiceInfo.issuer_cert_file_name(use_pem=True)
        return f"{self.full_relative_url}/{fname}"

    def issued_cert_url(self, label: CertLabel, use_pem=True):
        path = self.issued_cert_url_path(label=label, use_pem=use_pem)
        return f"{self.url}/{path}"


# TODO Add to Illusionist

@dataclass(frozen=True)
class AttrCertRepoServiceInfo(BaseCertRepoServiceInfo):
    base_url = '/attr-certs'
    publish_by_holder: bool = True

    @staticmethod
    def issuer_cert_file_name(use_pem=True):
        fname = f"aa.{'cert.pem' if use_pem else 'crt'}"
        return f"{fname}"

    @classmethod
    def issued_cert_url_path(cls, label: CertLabel, use_pem=True):
        fname = f"{label}.{'attr.cert.pem' if use_pem else 'attr.crt'}"
        return f"issued/{fname}"

    @classmethod
    def by_holder_url_path(cls, label: EntityLabel, use_pem=True):
        fname = f"{label}-all.{'attr.cert.pem' if use_pem else 'attr.p7b'}"
        return f"by-holder/{fname}"

    def issuer_cert_url(self, use_pem=True):
        fname = AttrCertRepoServiceInfo.issuer_cert_file_name(use_pem=use_pem)
        return f"{self.url}/{fname}"

    @property
    def issuer_cert_external_url(self):
        fname = AttrCertRepoServiceInfo.issuer_cert_file_name(use_pem=True)
        return f"{self.url}/{fname}"

    @property
    def issuer_cert_full_relative_url(self):
        fname = AttrCertRepoServiceInfo.issuer_cert_file_name(use_pem=True)
        return f"{self.full_relative_url}/{fname}"

    def issued_cert_url(self, label: CertLabel, use_pem=True):
        path = AttrCertRepoServiceInfo.issued_cert_url_path(
            label=label, use_pem=use_pem
        )
        return f"{self.url}/{path}"

    def issued_to_holder_url(self, label: EntityLabel, use_pem=True):
        path = AttrCertRepoServiceInfo.by_holder_url_path(
            label=label, use_pem=use_pem
        )
        return f"{self.url}/{path}"


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


class OCSPInterface(RevocationInfoInterface):

    def __init__(self, for_issuer: EntityLabel, pki_arch: PKIArchitecture,
                 issuer_cert_label: CertLabel, is_aa_responder: bool = False):
        self.for_issuer = for_issuer
        self.pki_arch = pki_arch
        self.issuer_cert_label = issuer_cert_label
        self.is_aa_responder = is_aa_responder

    def get_issuer_cert(self) -> x509.Certificate:
        return self.pki_arch.get_cert(self.issuer_cert_label)

    def check_revocation_status(self, cid: ocsp.CertId, at_time: datetime) \
            -> Tuple[ocsp.CertStatus, List[ocsp.SingleResponseExtension]]:
        cert_label = self.pki_arch.find_cert_label(
            cid, issuer_label=self.for_issuer, is_ac=self.is_aa_responder
        )
        revo = self.pki_arch.check_revocation_status(
            cert_label, at_time, is_ac=self.is_aa_responder
        )

        if revo is None:
            return ocsp.CertStatus('good'), []
        else:
            exts = [
                ext.to_asn1(self.pki_arch, ocsp.SingleResponseExtension)
                for ext in revo.ocsp_response_extensions
            ]
            return revo.to_ocsp_asn1(), exts


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
    plugin_label: str = None

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

    def invoke(self, arch: PKIArchitecture, info: PluginServiceInfo,
               request: bytes, at_time: Optional[datetime] = None) -> bytes:
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

    def invoke_plugin(self, arch: PKIArchitecture, info: PluginServiceInfo,
                      request: bytes,
                      at_time: Optional[datetime] = None) -> bytes:
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


DEFAULT_SRV_PLUGIN_REGISTRY = service_plugin_registry = ServicePluginRegistry()
"""
The default extension plugin registry.
"""


class ServiceRegistry:
    """
    Dispatcher class to interact with services associated with a PKI
    architecture.
    """

    def __init__(self, pki_arch: PKIArchitecture, external_url_prefix,
                 service_config, plugins: ServicePluginRegistry = None):
        self.pki_arch = pki_arch
        self.plugins = plugins or DEFAULT_SRV_PLUGIN_REGISTRY

        def _gen_svc_config(configs):
            for lbl, cfg in configs.items():
                cfg = dict(cfg)
                cfg.setdefault('external-url-prefix', external_url_prefix)
                cfg['label'] = lbl
                cfg['arch_label'] = pki_arch.arch_label.value
                yield ServiceLabel(lbl), cfg

        check_config_keys(
            'services', (
                'ocsp', 'crl-repo', 'cert-repo', 'attr-cert-repo',
                'time-stamping', 'plugin'
            ),
            service_config
        )

        self._ocsp = {
            label: OCSPResponderServiceInfo.from_config(cfg)
            for label, cfg
            in _gen_svc_config(service_config.get('ocsp', {}))
        }
        self._crl_repo = {
            label: CRLRepoServiceInfo.from_config(cfg)
            for label, cfg
            in _gen_svc_config(service_config.get('crl-repo', {}))
        }
        self._cert_repo = {
            label: CertRepoServiceInfo.from_config(cfg)
            for label, cfg
            in _gen_svc_config(service_config.get('cert-repo', {}))
        }
        self._attr_cert_repo = {
            label: AttrCertRepoServiceInfo.from_config(cfg)
            for label, cfg
            in _gen_svc_config(service_config.get('attr-cert-repo', {}))
        }
        self._tsa = {
            label: TSAServiceInfo.from_config(cfg)
            for label, cfg
            in _gen_svc_config(service_config.get('time-stamping', {}))
        }

        plugin_cfg = service_config.get('plugin', {})

        # TODO type checks with better error reporting

        def _cfg_plugin(plugin_label, cfg_for_plugin):
            plugin = self.plugins[plugin_label]
            content_type = plugin.content_type
            svc_configs = _gen_svc_config(cfg_for_plugin)
            for service_label, cfg in svc_configs:
                yield service_label, PluginServiceInfo(
                    plugin_label=plugin_label, content_type=content_type,
                    plugin_config=plugin.process_plugin_config(cfg),
                    label=service_label,
                    external_url_prefix=cfg['external-url-prefix'],
                    arch_label=pki_arch.arch_label
                )

        self._plugin_services = {
            PluginLabel(plugin_label):
                dict(_cfg_plugin(PluginLabel(plugin_label), cfg))
            for plugin_label, cfg in plugin_cfg.items()
        }

    def get_ocsp_info(self, label: ServiceLabel) -> OCSPResponderServiceInfo:
        try:
            return self._ocsp[label]
        except KeyError as e:
            raise CertomancerObjectNotFoundError(
                f"There is no registered OCSP service labelled '{label}'."
            ) from e

    def list_ocsp_responders(self) -> List[OCSPResponderServiceInfo]:
        return list(self._ocsp.values())

    def summon_responder(self, label: ServiceLabel, at_time=None) \
            -> SimpleOCSPResponder:
        info = self.get_ocsp_info(label)
        responder_key = self.pki_arch.key_set.get_private_key(info.signing_key)
        issuer_cert_label = info.resolve_issuer_cert(self.pki_arch)

        extra_extensions = [
            ext.to_asn1(self.pki_arch, ocsp.ResponseDataExtension)
            for ext in info.ocsp_extensions
        ]
        responder_cert = self.pki_arch.get_cert(info.responder_cert)
        return SimpleOCSPResponder(
            responder_cert=responder_cert,
            responder_key=responder_key,
            signature_algo=choose_signed_digest(
                info.digest_algo, responder_cert.public_key,
                signature_algo=info.signature_algo
            ),
            at_time=at_time,
            revinfo_interface=OCSPInterface(
                for_issuer=info.for_issuer, pki_arch=self.pki_arch,
                issuer_cert_label=issuer_cert_label,
                is_aa_responder=info.is_aa_responder
            ),
            response_extensions=extra_extensions
        )

    def get_crl_repo_info(self, label: ServiceLabel) -> CRLRepoServiceInfo:
        try:
            return self._crl_repo[label]
        except KeyError as e:
            raise CertomancerObjectNotFoundError(
                f"There is no registered CRL repository labelled '{label}'."
            ) from e

    def list_crl_repos(self) -> List[CRLRepoServiceInfo]:
        return list(self._crl_repo.values())

    def get_cert_repo_info(self, label: ServiceLabel) -> CertRepoServiceInfo:
        try:
            return self._cert_repo[label]
        except KeyError as e:
            raise CertomancerObjectNotFoundError(
                f"There is no registered certificate repository "
                f"labelled '{label}'."
            ) from e

    def get_attr_cert_repo_info(self, label: ServiceLabel) \
            -> AttrCertRepoServiceInfo:
        try:
            return self._attr_cert_repo[label]
        except KeyError as e:
            raise CertomancerObjectNotFoundError(
                f"There is no registered attribute certificate repository "
                f"labelled '{label}'."
            ) from e

    def list_cert_repos(self) -> List[CertRepoServiceInfo]:
        return list(self._cert_repo.values())

    def list_attr_cert_repos(self) -> List[AttrCertRepoServiceInfo]:
        return list(self._attr_cert_repo.values())

    def get_tsa_info(self, label: ServiceLabel) -> TSAServiceInfo:
        try:
            return self._tsa[label]
        except KeyError as e:
            raise CertomancerObjectNotFoundError(
                f"There is no registered time stamping service "
                f"labelled '{label}'."
            ) from e

    def list_time_stamping_services(self) -> List[TSAServiceInfo]:
        return list(self._tsa.values())

    def summon_timestamper(self, label: ServiceLabel, at_time=None) \
            -> TimeStamper:
        # TODO allow policy parameter to be customised
        info = self.get_tsa_info(label)
        tsa_key = self.pki_arch.key_set.get_private_key(info.signing_key)
        tsa_cert = self.pki_arch.get_cert(info.signing_cert)
        return TimeStamper(
            tsa_cert=tsa_cert,
            tsa_key=tsa_key,
            fixed_dt=at_time,
            signature_algo=choose_signed_digest(
                info.digest_algo, pub_key=tsa_cert.public_key,
                signature_algo=info.signature_algo
            ),
            certs_to_embed=[
                self.pki_arch.get_cert(lbl) for lbl in info.certs_to_embed
            ],
            md_algorithm=info.digest_algo
        )

    def get_crl(self, repo_label: ServiceLabel,
                at_time: Optional[datetime] = None,
                number: Optional[int] = None):
        # TODO support indirect CRLs, delta CRLs, etc.?

        crl_info = self.get_crl_repo_info(repo_label)
        issuer_cert_label = crl_info.issuer_cert
        signing_key_pair = \
            self.pki_arch.key_set.get_asym_key(crl_info.signing_key)
        signing_key = signing_key_pair.private

        # we need a cert to compute the right authority key identifier,
        # time origin etc.
        if issuer_cert_label is None:
            issuer_cert_label = crl_info.resolve_issuer_cert(self.pki_arch)
        iss_cert = self.pki_arch.get_cert(issuer_cert_label)

        time_origin = iss_cert.not_valid_before
        time_delta = crl_info.simulated_update_schedule

        if number is None:
            if at_time is None:
                at_time = datetime.now(tz=tzlocal.get_localzone())
            # work backwards to find a reasonable CRL number
            elapsed = at_time - time_origin
            if elapsed < timedelta(0):
                raise CertomancerServiceError(
                    "CRL timestamp is before validity period of issuer cert; "
                    "could not deduce a reasonable CRL number. If you are "
                    "trying to create a questionable CRL on purpose, pass in a "
                    "CRL number manually."
                )
            number = elapsed // time_delta
        this_update = time_origin + number * time_delta
        next_update = this_update + time_delta

        extra_extensions = [
            ext.to_asn1(self.pki_arch, crl.TBSCertListExtension)
            for ext in crl_info.crl_extensions
        ]
        builder = CRLBuilder(
            issuer_name=self.pki_arch.entities[crl_info.for_issuer],
            issuer_key=signing_key,
            signature_algo=choose_signed_digest(
                crl_info.digest_algo, signing_key_pair.public,
                signature_algo=crl_info.signature_algo
            ),
            authority_key_identifier=iss_cert.key_identifier_value,
            extra_crl_extensions=extra_extensions
        )

        revoked = []
        if crl_info.crl_type != CRLType.AC_ONLY:
            revoked.extend(
                self.pki_arch.get_revoked_certs_at_time(
                    issuer_label=crl_info.for_issuer, at_time=this_update
                )
            )
        if crl_info.crl_type not in (CRLType.CA_ONLY, CRLType.USER_ONLY):
            revoked.extend(
                self.pki_arch.get_revoked_attr_certs_at_time(
                    issuer_label=crl_info.for_issuer, at_time=this_update
                )
            )
        return builder.build_crl(
            crl_number=number, this_update=this_update,
            next_update=next_update, revoked_certs=revoked,
            distpoint=crl_info.format_idp()
        )

    def determine_repo_issuer_cert(self, repo_info: BaseCertRepoServiceInfo):
        # return the issuer's certificate
        cert_label = repo_info.issuer_cert
        if cert_label is None:
            issuer = repo_info.for_issuer
            # TODO: Should we return None if the issuer cert can't be
            #  determined, or let the error propagate?
            #  Choosing the latter for now.
            cert_label = self.pki_arch.get_unique_cert_for_entity(issuer)
        return cert_label

    def _check_repo_membership(self, repo_info: BaseCertRepoServiceInfo,
                               cert_label: CertLabel, is_attr=False):
        # check if the cert in question actually belongs to the repo
        # (i.e. whether it is issued by the right entity)
        if is_attr:
            cert_spec = self.pki_arch.get_attr_cert_spec(cert_label)
        else:
            cert_spec = self.pki_arch.get_cert_spec(cert_label)

        return cert_spec.issuer == repo_info.for_issuer

    def get_cert_from_repo(self, repo_label: ServiceLabel,
                           cert_label: Optional[CertLabel] = None) \
            -> Optional[x509.Certificate]:

        repo_info = self.get_cert_repo_info(repo_label)
        arch = self.pki_arch
        if cert_label is None:
            cert_label = self.determine_repo_issuer_cert(repo_info)
        elif not self._check_repo_membership(repo_info, cert_label):
            return None
        return arch.get_cert(cert_label)

    def get_attr_cert_from_repo(self, repo_label: ServiceLabel,
                                cert_label: CertLabel) \
            -> Optional[cms.AttributeCertificateV2]:

        repo_info = self.get_attr_cert_repo_info(repo_label)
        if not self._check_repo_membership(repo_info, cert_label, is_attr=True):
            return None
        return self.pki_arch.get_attr_cert(cert_label)

    def invoke_plugin(self, plugin_label: PluginLabel,
                      label: ServiceLabel, request: bytes,
                      at_time: Optional[datetime] = None) -> bytes:
        info = self.get_plugin_info(plugin_label, label)
        return self.plugins.invoke_plugin(
            self.pki_arch, info, request, at_time=at_time
        )

    def get_plugin_info(self, plugin_label: PluginLabel, label: ServiceLabel) \
            -> PluginServiceInfo:
        self.plugins.assert_registered(plugin_label)
        try:
            svcs_for_plugin = self._plugin_services.get(plugin_label, {})
            return svcs_for_plugin[label]
        except KeyError as e:
            raise ConfigurationError(
                f"The plugin-service combination '{plugin_label}'-'{label}' "
                f"does not exist."
            ) from e

    def list_plugin_services(self, plugin_label: Optional[PluginLabel] = None)\
            -> List[PluginServiceInfo]:
        svcs = self._plugin_services

        def _enumerate_svcs(*relevant_plugins):
            for plg in relevant_plugins:
                yield from svcs[plg].values()

        if plugin_label is not None:
            self.plugins.assert_registered(plugin_label)
            return list(_enumerate_svcs(plugin_label))
        else:
            return list(_enumerate_svcs(*svcs.keys()))


DEFAULT_PLUGIN_MODULE = "certomancer.default_plugins"


def _import_plugin_modules(plugins):
    if not isinstance(plugins, (list, tuple)):
        raise ConfigurationError("Plugin modules must be specified as a list")

    def _do_import(module):
        try:
            importlib.import_module(module)
        except ImportError as e:
            raise ConfigurationError(
                f"Failed to import plugin module {module}."
            ) from e

    _do_import(DEFAULT_PLUGIN_MODULE)
    for plug in plugins:
        logger.debug(f"Importing plugins in module {plug}...")
        _do_import(plug)


class CertomancerConfig:
    """
    Helper class to interpret & manage Certomancer configuration information.
    """

    DEFAULT_EXTERNAL_URL_PREFIX = 'http://ca.example.com'
    EXTERNAL_URL_PREFIX_VARIABLE = 'external-url-prefix'

    @classmethod
    def from_yaml(cls, yaml_str, key_search_dir,
                  config_search_dir=None,
                  external_url_prefix=None) -> 'CertomancerConfig':
        config_dict = yaml.safe_load(yaml_str)
        return CertomancerConfig(
            config_dict, key_search_dir=key_search_dir,
            config_search_dir=config_search_dir,
            external_url_prefix=external_url_prefix
        )

    @classmethod
    def from_file(cls, cfg_path, key_search_dir=None, config_search_dir=None,
                  allow_external_config=True,
                  external_url_prefix=None) -> 'CertomancerConfig':
        main_config_dir = os.path.dirname(cfg_path)
        if not allow_external_config:
            config_search_dir = None
        elif config_search_dir is None:
            config_search_dir = main_config_dir
        key_search_dir = key_search_dir or main_config_dir
        with open(cfg_path, 'r') as inf:
            config_dict = yaml.safe_load(inf)
        return CertomancerConfig(
            config_dict, key_search_dir=key_search_dir,
            config_search_dir=config_search_dir,
            external_url_prefix=external_url_prefix
        )

    def __init__(self, config, key_search_dir: str,
                 lazy_load_keys=False, config_search_dir: Optional[str] = None,
                 external_url_prefix=None):
        if external_url_prefix is None:
            self.external_url_prefix = external_url_prefix = config.get(
                'external-url-prefix', self.DEFAULT_EXTERNAL_URL_PREFIX
            )

        extn_plugin_list = config.get('plugin-modules', ())
        _import_plugin_modules(extn_plugin_list)

        try:
            key_set_cfg = config['keysets']
        except KeyError as e:
            raise ConfigurationError(
                "'keysets' must be present in configuration"
            ) from e

        self.key_sets = key_sets = KeySets(
            key_set_cfg, lazy_load_keys=lazy_load_keys,
            search_dir=SearchDir(key_search_dir)
        )
        try:
            arch_cfgs = config['pki-architectures']
        except KeyError as e:
            raise ConfigurationError(
                "'pki-architectures' must be present in configuration"
            ) from e

        if config_search_dir is not None:
            config_search_dir = SearchDir(config_search_dir)
        self.pki_archs = {
            arch.arch_label: arch
            for arch in PKIArchitecture.build_architectures(
                key_sets, arch_cfgs, external_url_prefix=external_url_prefix,
                config_search_dir=config_search_dir
            )
        }

    def get_pki_arch(self, label: ArchLabel) -> PKIArchitecture:
        try:
            return self.pki_archs[label]
        except KeyError as e:
            raise ConfigurationError(
                f"There is no PKI architecture with label {label}."
            ) from e
