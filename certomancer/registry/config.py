import importlib
import logging
import os
import os.path
from typing import Optional

import yaml

from ..config_utils import ConfigurationError, SearchDir
from .common import ArchLabel
from .keys import KeySets
from .pki_arch import PKIArchitecture

__all__ = ['CertomancerConfig']

logger = logging.getLogger(__name__)


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
    def from_yaml(
        cls,
        yaml_str,
        key_search_dir,
        config_search_dir=None,
        external_url_prefix=None,
    ) -> 'CertomancerConfig':
        config_dict = yaml.safe_load(yaml_str)
        return CertomancerConfig(
            config_dict,
            key_search_dir=key_search_dir,
            config_search_dir=config_search_dir,
            external_url_prefix=external_url_prefix,
        )

    @classmethod
    def from_file(
        cls,
        cfg_path,
        key_search_dir=None,
        config_search_dir=None,
        allow_external_config=True,
        external_url_prefix=None,
    ) -> 'CertomancerConfig':
        main_config_dir = os.path.dirname(cfg_path)
        if not allow_external_config:
            config_search_dir = None
        elif config_search_dir is None:
            config_search_dir = main_config_dir
        key_search_dir = key_search_dir or main_config_dir
        with open(cfg_path, 'r') as inf:
            config_dict = yaml.safe_load(inf)
        return CertomancerConfig(
            config_dict,
            key_search_dir=key_search_dir,
            config_search_dir=config_search_dir,
            external_url_prefix=external_url_prefix,
        )

    def __init__(
        self,
        config,
        key_search_dir: str,
        lazy_load_keys=False,
        config_search_dir: Optional[str] = None,
        external_url_prefix=None,
    ):
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
            key_set_cfg,
            lazy_load_keys=lazy_load_keys,
            search_dir=SearchDir(key_search_dir),
        )
        try:
            arch_cfgs = config['pki-architectures']
        except KeyError as e:
            raise ConfigurationError(
                "'pki-architectures' must be present in configuration"
            ) from e

        search_dir = (
            SearchDir(config_search_dir)
            if config_search_dir is not None
            else None
        )
        self.pki_archs = {
            arch.arch_label: arch
            for arch in PKIArchitecture.build_architectures(
                key_sets,
                arch_cfgs,
                external_url_prefix=external_url_prefix,
                config_search_dir=search_dir,
            )
        }

    def get_pki_arch(self, label: ArchLabel) -> PKIArchitecture:
        try:
            return self.pki_archs[label]
        except KeyError as e:
            raise ConfigurationError(
                f"There is no PKI architecture with label {label}."
            ) from e
