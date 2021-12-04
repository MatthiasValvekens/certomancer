import binascii
import itertools
from typing import Optional

from asn1crypto import x509, core, cms
from asn1crypto.core import ObjectIdentifier

from dateutil.parser import parse as parse_dt
from .config_utils import ConfigurationError, check_config_keys, \
    key_dashes_to_underscores
from .registry import ExtensionPlugin, PKIArchitecture, \
    extension_plugin_registry, attr_plugin_registry, \
    ServiceLabel, CertLabel, EntityRegistry, EntityLabel, AttributePlugin

__all__ = [
    'CRLDistributionPointsPlugin', 'KeyUsagePlugin', 'AIAUrlPlugin',
    'GeneralNamesPlugin', 'ACTargetsPlugin',
    'IetfAttrSyntaxPlugin', 'RoleSyntaxPlugin', 'ServiceAuthInfoPlugin'
]


@extension_plugin_registry.register
class CRLDistributionPointsPlugin(ExtensionPlugin):
    schema_label = 'crl-dist-url'
    extension_type = x509.ExtensionId

    def provision(self, extn_id, arch: PKIArchitecture, params):
        try:
            repo_names = params['crl-repo-names']
        except KeyError:
            raise ConfigurationError(
                "The parameter crl-repo-names is required."
            )

        def _distpoints():
            for repo_name in repo_names:
                repo_info = arch.service_registry.get_crl_repo_info(repo_name)
                yield repo_info.format_distpoint()
        return list(_distpoints())


@extension_plugin_registry.register
class AIAUrlPlugin(ExtensionPlugin):
    schema_label = 'aia-urls'
    extension_type = x509.ExtensionId

    def provision(self, extn_id, arch: PKIArchitecture, params):
        # TODO support subjectInfoAccess as well
        #  (i.e. time_stamping, ca_repository)
        try:
            ocsp_names = params['ocsp-responder-names']
            if not isinstance(ocsp_names, list):
                raise ConfigurationError(
                    "ocsp-responder-names must be a list"
                )
        except KeyError:
            ocsp_names = ()

        services = arch.service_registry

        def _ocsps():
            for name in ocsp_names:
                ocsp_info = services.get_ocsp_info(name)
                yield {
                    'access_method': 'ocsp',
                    'access_location': {
                        'uniform_resource_identifier': ocsp_info.url
                    }
                }

        try:
            ca_issuer_links = params['ca-issuer-links']
            if not isinstance(ca_issuer_links, list):
                raise ConfigurationError(
                    "ca-issuer-links must be a list"
                )
        except KeyError:
            ca_issuer_links = []

        def _ca_issuer_links():
            for cfg in ca_issuer_links:
                check_config_keys(
                    'ca-issuer-links',
                    ('repo', 'cert-labels', 'include-repo-authority'),
                    cfg
                )

                # grab labels of the repo & certs we want to include
                # from the configuration parameters
                try:
                    repo_name = cfg['repo']
                except KeyError as e:
                    raise ConfigurationError(
                        "ca-issuer-links entry must specify 'repo' key."
                    ) from e

                issuer_certs = map(CertLabel, cfg.get('cert-labels', ()))
                authority = cfg.get('include-repo-authority', True)

                # look up the service info object for the cert repo in question
                cert_repo_info = services.get_cert_repo_info(
                    ServiceLabel(repo_name)
                )
                # emit URL to repo authority if requested
                if authority:
                    yield {
                        'access_method': 'ca_issuers',
                        'access_location': {
                            'uniform_resource_identifier':
                                cert_repo_info.issuer_cert_url(use_pem=False)
                        }
                    }

                # emit URLs to certificates in repo
                # TODO add an option to bundle certs in a "certs-only"
                #  PKCS#7 object
                for cert_label in issuer_certs:
                    yield {
                        'access_method': 'ca_issuers',
                        'access_location': {
                            'uniform_resource_identifier':
                                cert_repo_info.issued_cert_url(
                                    cert_label, use_pem=False
                                )
                        }
                    }

        return list(itertools.chain(_ocsps(), _ca_issuer_links()))


@extension_plugin_registry.register
class KeyUsagePlugin(ExtensionPlugin):
    schema_label = 'key-usage'
    extension_type = x509.ExtensionId

    def provision(self, extn_id, arch: 'PKIArchitecture', params):
        # asn1crypto doesn't accept a list to construct a bit string object
        return x509.KeyUsage(set(params))


# some convenient aliases
NAME_TYPE_ALIASES = {
    'email': 'rfc822_name',
    'uri': 'uniform_resource_identifier',
    'ip': 'ip_address',
}


def process_general_name(entities: EntityRegistry, params):

    check_config_keys('general name', ('type', 'value'), params)
    try:
        name_type = params['type'].replace('-', '_')
        value = params['value']
    except KeyError:
        raise ConfigurationError(
            "A general name should be specified as a dictionary with a 'type' "
            "key and a 'value' key."
        )
    # resolve convenience abbreviations
    name_type = NAME_TYPE_ALIASES.get(name_type, name_type)

    if name_type == 'directory_name':
        # values for directory names get special treatment
        if isinstance(value, dict):
            value = x509.Name.build(key_dashes_to_underscores(value))
        elif isinstance(value, str):
            value = entities[EntityLabel(value)]
        else:
            raise ConfigurationError(
                "Directory names require a dictionary with fields, or a string "
                "(interpreted as an entity label)."
            )
    return x509.GeneralName(name=name_type, value=value)


@extension_plugin_registry.register
class GeneralNamesPlugin(ExtensionPlugin):
    schema_label = 'general-names'
    extension_type = None  # not tied to any particular extension type

    def provision(self, extn_id, arch: 'PKIArchitecture', params):
        if not isinstance(params, list):
            raise ConfigurationError(
                "Parameters for general-names should be specified as a list"
            )

        return [process_general_name(arch.entities, p) for p in params]


@extension_plugin_registry.register
class ACTargetsPlugin(ExtensionPlugin):
    schema_label = 'ac-targets'
    extension_type = x509.ExtensionId

    @staticmethod
    def _parse_target(entities, params):

        if isinstance(params, str):
            name = x509.GeneralName(
                name='directory_name', value=entities[EntityLabel(params)]
            )
            is_group = False
        elif isinstance(params, dict):
            params = dict(params)
            # remove the is_group key
            is_group = bool(params.pop('is-group', False))
            # treat the rest as a general name designation
            name = process_general_name(entities, params)
        else:
            raise ConfigurationError(
                "Target designation must be either a string or a dictionary"
            )
        return name, is_group

    def provision(self, extn_id, arch: 'PKIArchitecture', params):
        from ._asn1_types import Target, Targets, SequenceOfTargets
        if isinstance(params, list):
            targets = (
                ACTargetsPlugin._parse_target(arch.entities, t)
                for t in params
            )
        else:
            targets = (ACTargetsPlugin._parse_target(arch.entities, params),)

        target_objs = [
            Target(
                name='target_group' if is_group else 'target_name',
                value=name
            )
            for name, is_group in targets
        ]
        value = SequenceOfTargets([Targets(target_objs)])
        # Convert to octet string directly to avoid exposing internal types,
        # and to avoid internal types clashing with external ones that might
        # be registered in asn1crypto
        return core.ParsableOctetString(value.dump())


@attr_plugin_registry.register
class RoleSyntaxPlugin(AttributePlugin):
    schema_label = 'role-syntax'

    def provision(self, attr_id, arch: 'PKIArchitecture', params):
        if not isinstance(params, dict):
            raise ConfigurationError(
                "Parameters for role-syntax should be specified as a dict"
            )
        check_config_keys(
            'role-syntax', ('name', 'authority'), params
        )
        try:
            name_params = params['name']
        except KeyError:
            raise ConfigurationError("role-syntax requires a name entry")
        role_name = process_general_name(arch.entities, name_params)
        try:
            authority_params = params['authority']
            if not isinstance(authority_params, list):
                raise ConfigurationError(
                    "Parameters for role authority should be specified as "
                    "a list"
                )
        except KeyError:
            authority_params = None
        result = {'role_name': role_name}
        if authority_params is not None:
            authority = [
                process_general_name(arch.entities, p) for p in authority_params
            ]
            result['role_authority'] = authority
        return cms.RoleSyntax(result)


def _parse_ietf_attr_value(params):
    if isinstance(params, str):
        alt = 'string'
        value = core.UTF8String(params)
    elif isinstance(params, dict):
        check_config_keys(
            'IETF attribute syntax constituent value', ('type', 'value'), params
        )
        try:
            alt = params['type']
            value_pre = params['value']
        except KeyError:
            raise ConfigurationError(
                "'type' and 'value' entries are required in an "
                "an IETF attribute syntax constituent value dictionary."
            )

        if not isinstance(value_pre, str):
            raise ConfigurationError(
                "The 'value' entry in an IETF attribute syntax constituent "
                "value dictionary must be a string"
            )
        if alt == 'string':
            value = core.UTF8String(value_pre)
        elif alt == 'oid':
            try:
                value = core.ObjectIdentifier(value=value_pre)
                value.dump()
            except ValueError:
                raise ConfigurationError(
                    f"IETF attribute syntax constituent value of type 'oid' "
                    f"must be a valid dotted OID string, not '{value_pre}'."
                )
        elif alt == 'octets':
            try:
                value = core.OctetString(
                    value=binascii.unhexlify(value_pre)
                )
            except ValueError:
                raise ConfigurationError(
                    f"IETF attribute syntax constituent value of type 'octets' "
                    f"must be a valid hex string, not '{value_pre}'."
                )
        else:
            raise ConfigurationError(
                "The 'type' entry in an IETF attribute syntax constituent "
                "value dictionary must be one of 'oid', 'octets' or 'string', "
                f"not '{alt}'"
            )
    else:
        raise ConfigurationError(
            "An IETF attribute syntax constituent value is given by "
            f"a string or a dict, not {type(params)}."
        )
    return cms.IetfAttrValue(name=alt, value=value)


@attr_plugin_registry.register
class IetfAttrSyntaxPlugin(AttributePlugin):
    schema_label = 'ietf-attribute'

    def provision(self, attr_id, arch: 'PKIArchitecture', params):
        if isinstance(params, dict):
            check_config_keys(
                'ietf-attribute', ('values', 'authority'), params
            )
            try:
                values = params['values']
                if not isinstance(values, list):
                    raise ConfigurationError(
                        "'values' in ietf-attribute should be a list"
                    )
            except KeyError:
                raise ConfigurationError(
                    "ietf-attribute requires a 'values' entry "
                    "when specified as a dict"
                )
            try:
                policy_authority = params['authority']
                if not isinstance(policy_authority, list):
                    raise ConfigurationError(
                        "'authority' in ietf-attribute should be a list"
                    )
            except KeyError:
                policy_authority = None
        elif isinstance(params, list):
            values = params
            policy_authority = None
        else:
            raise ConfigurationError(
                "Parameters for ietf-attribute should be specified as a dict "
                "or a list"
            )

        result = {'values': [_parse_ietf_attr_value(p) for p in values]}
        if policy_authority is not None:
            result['policy_authority'] = [
                process_general_name(arch.entities, p) for p in policy_authority
            ]
        return cms.IetfAttrSyntax(result)


@attr_plugin_registry.register
class ServiceAuthInfoPlugin(AttributePlugin):
    schema_label = 'service-auth-info'

    def provision(self, attr_id: Optional[ObjectIdentifier],
                  arch: 'PKIArchitecture', params):

        if not isinstance(params, dict):
            raise ConfigurationError(
                "Parameters for service-auth-info should be specified as a dict"
            )

        check_config_keys(
            'service-auth-info', ('service', 'ident', 'auth-info'),
            params
        )

        try:
            service_raw = params['service']
            ident_raw = params['ident']
        except KeyError:
            raise ConfigurationError(
                "'service' and 'ident' are required in a service-auth-info "
                "attribute value."
            )

        service = process_general_name(arch.entities, service_raw)
        ident = process_general_name(arch.entities, ident_raw)
        result = {'service': service, 'ident': ident}

        try:
            auth_info = params['auth-info']
            if not isinstance(auth_info, str):
                raise ConfigurationError("'auth-info' must be a hex string")
        except KeyError:
            auth_info = None

        if auth_info is not None:
            try:
                result['auth_info'] = core.OctetString(
                    binascii.unhexlify(auth_info)
                )
            except ValueError:
                raise ConfigurationError("'auth-info' must be a hex string")
        return cms.SvceAuthInfo(result)


@extension_plugin_registry.register
class IsoTimePlugin(ExtensionPlugin):
    schema_label = 'iso-time'
    extension_type = None

    def provision(self, extn_id, arch: 'PKIArchitecture', params):
        if not isinstance(params, str):
            raise ConfigurationError(
                "'params' entry for iso-time plugin should be a string."
            )
        return core.GeneralizedTime(parse_dt(params))


@extension_plugin_registry.register
class RawDERBytes(ExtensionPlugin):

    schema_label = 'der-bytes'
    extension_type = None

    def provision(self, extn_id, arch: 'PKIArchitecture', params):
        der_bytes = None
        try:
            if isinstance(params, str):
                der_bytes = binascii.unhexlify(params)
        except ValueError:
            pass

        if der_bytes is None:
            raise ConfigurationError(
                "'params' entry for der-bytes plugin should be a hexadecimal "
                "string."
            )

        return core.ParsableOctetString(der_bytes)
