from asn1crypto import x509

from .config_utils import ConfigurationError
from .registry import SmartValueProcessor, PKIArchitecture


class CRLDistributionPointsProc(SmartValueProcessor):
    schema_label = 'crl-dist-url'

    def provision(self, arch: PKIArchitecture, params):
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


class AIAUrlProc(SmartValueProcessor):
    schema_label = 'aia-urls'

    def provision(self, arch: PKIArchitecture, params):
        # TODO support other AIA entries: ca_issuers, time_stamping,
        #  ca_repository
        try:
            ocsp_names = params['ocsp-responder-names']
            if not isinstance(ocsp_names, list):
                raise ConfigurationError(
                    "ocsp-responder-names must be a list"
                )
        except KeyError:
            ocsp_names = []

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

        return list(_ocsps())


class KeyUsageProc(SmartValueProcessor):
    schema_label = 'key-usage'

    def provision(self, arch: 'PKIArchitecture', params):
        # asn1crypto doesn't accept a list to construct a bit string object
        return x509.KeyUsage(set(params))

