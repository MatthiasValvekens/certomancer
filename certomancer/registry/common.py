from certomancer.config_utils import LabelString
from certomancer.services import CertomancerServiceError

__all__ = [
    'CertomancerObjectNotFoundError',
    'KeyLabel',
    'CertLabel',
    'EntityLabel',
    'ServiceLabel',
    'PluginLabel',
    'ArchLabel',
]


class CertomancerObjectNotFoundError(CertomancerServiceError):
    pass


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
