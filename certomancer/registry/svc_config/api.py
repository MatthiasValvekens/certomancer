from dataclasses import dataclass
from typing import ClassVar

from ...config_utils import ConfigurableMixin
from ..common import ArchLabel, ServiceLabel

__all__ = ['ServiceInfo']


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
