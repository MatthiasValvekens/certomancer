import copy
from dataclasses import dataclass
from typing import Optional

from asn1crypto.keys import PrivateKeyInfo, PublicKeyInfo

from ..config_utils import (
    ConfigurationError,
    SearchDir,
    check_config_keys,
    get_and_apply,
)
from ..crypto_utils import load_private_key, load_public_key
from .common import CertomancerObjectNotFoundError, KeyLabel


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

    def __init__(
        self,
        name: KeyLabel,
        path: str,
        public_only: bool = False,
        password=None,
    ):
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
            try:
                with open(self.path, 'rb') as keyf:
                    key_bytes = keyf.read()
                if self.public_only:
                    public = load_public_key(key_bytes)
                    private = None
                else:
                    private, public = load_private_key(key_bytes, self.password)
            except Exception as e:
                raise IOError(
                    f"Failed to load key in {self.path}.\nGenerate one with "
                    f"`openssl genrsa -out {repr(self.path)}` (RSA example) "
                    f"or another appropriate tool."
                ) from e
            self._key = AsymKey(public=public, private=private)

    @property
    def public_key_info(self) -> PublicKeyInfo:
        self._load()
        key = self._key
        assert key is not None
        return key.public

    @property
    def private_key_info(self) -> Optional[PrivateKeyInfo]:
        self._load()
        key = self._key
        assert key is not None
        return key.private

    @property
    def key_pair(self) -> AsymKey:
        self._load()
        key = self._key
        assert key is not None
        return key


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
