import itertools

from asn1crypto import x509, core

from dateutil.parser import parse as parse_dt
from .config_utils import ConfigurationError, check_config_keys, \
    key_dashes_to_underscores
from .registry import ExtensionPlugin, PKIArchitecture, \
    extension_plugin_registry, ServiceLabel, CertLabel, EntityRegistry, \
    EntityLabel

__all__ = [
    'CRLDistributionPointsPlugin', 'KeyUsagePlugin', 'AIAUrlPlugin',
    'GeneralNamesPlugin'
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
class IsoTimePlugin(ExtensionPlugin):
    schema_label = 'iso-time'
    extension_type = None

    def provision(self, extn_id, arch: 'PKIArchitecture', params):
        if not isinstance(params, str):
            raise ConfigurationError(
                "'params' entry for iso-time plugin should be a string."
            )
        return core.GeneralizedTime(parse_dt(params))
