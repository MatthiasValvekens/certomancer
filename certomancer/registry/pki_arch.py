import copy
import itertools
import os
import os.path
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union
from zipfile import ZipFile

import tzlocal
import yaml
from asn1crypto import cms, core, crl, ocsp, pem, x509
from cryptography.hazmat.primitives._serialization import (
    KeySerializationEncryption,
)

from ..config_utils import (
    ConfigurationError,
    SearchDir,
    check_config_keys,
    key_dashes_to_underscores,
)
from ..crypto_utils import load_cert_from_pemder, pyca_cryptography_present
from ..services import (
    CertomancerServiceError,
    CRLBuilder,
    SimpleOCSPResponder,
    TimeStamper,
    choose_signed_digest,
    generic_sign,
)
from . import plugin_api
from .common import (
    ArchLabel,
    CertLabel,
    CertomancerObjectNotFoundError,
    EntityLabel,
    KeyLabel,
    PluginLabel,
    ServiceLabel,
)
from .entities import EntityRegistry, as_general_name
from .issued.attr_cert import AttributeCertificateSpec
from .issued.cert import CertificateSpec
from .issued.general import IssuedItemSpec, RevocationStatus
from .keys import KeySet, KeySets
from .plugin_api import (
    AttributePluginRegistry,
    CertProfilePluginRegistry,
    ExtensionPluginRegistry,
    PluginServiceInfo,
    ServicePluginRegistry,
    cert_profile_plugin_registry,
)
from .svc_config.cert_repo import (
    AttrCertRepoServiceInfo,
    BaseCertRepoServiceInfo,
    CertRepoServiceInfo,
)
from .svc_config.crl import CRLRepoServiceInfo, CRLType
from .svc_config.ocsp import OCSPInterface, OCSPResponderServiceInfo
from .svc_config.tsa import TSAServiceInfo

__all__ = [
    'PKIArchitecture',
    'ServiceRegistry',
]


@dataclass(frozen=True)
class _IssuedItemConfigState:
    serial_by_issuer: Dict[EntityLabel, int] = field(
        default_factory=lambda: defaultdict(lambda: DEFAULT_FIRST_SERIAL)
    )
    cert_labels_by_issuer: Dict[EntityLabel, List[CertLabel]] = field(
        default_factory=lambda: defaultdict(list)
    )


@dataclass(frozen=True)
class _CertSpecConfigState(_IssuedItemConfigState):

    cert_labels_by_subject: Dict[EntityLabel, List[CertLabel]] = field(
        default_factory=lambda: defaultdict(list)
    )
    cert_specs: Dict[CertLabel, CertificateSpec] = field(default_factory=dict)


def _config_issuer_serial(
    state: _IssuedItemConfigState, name, effective_cert_config
):

    try:
        issuer = effective_cert_config['issuer']
    except KeyError as e:
        raise ConfigurationError(
            f"Certificate spec {name} does not specify an issuer."
        ) from e
    effective_cert_config.setdefault('authority_key', issuer)
    serial = state.serial_by_issuer[EntityLabel(issuer)]
    effective_cert_config.setdefault('serial', serial)
    state.serial_by_issuer[EntityLabel(issuer)] = serial + 1
    return EntityLabel(issuer)


def _combine_extension_cfgs(explicit_exts, template_exts, unique_req: bool):
    # NOTE for backwards compat:
    #  extensions + template_extensions was the original order,
    #  so we need to make sure that's the order in which we process
    #  the keys when eliminating duplicates, to maximally maintain compatibility
    #  in terms of output (to the extent possible, that is).

    if unique_req:
        extensions = []
        seen = set()
        for ext_cfg in explicit_exts + template_exts:
            try:
                ext_id = ext_cfg['id']
            except KeyError:
                raise ConfigurationError(
                    "'id' is required in extension dictionaries"
                )
            if ext_id not in seen:
                extensions.append(ext_cfg)
                seen.add(ext_id)
    else:
        extensions = explicit_exts + template_exts
    return extensions


def _process_template_config(cert_specs, name, cert_config):
    template = cert_config.pop('template', None)
    if template is not None:
        # we want to merge extensions from the template
        extensions = cert_config.pop('extensions', [])
        try:
            template_spec: CertificateSpec = cert_specs[CertLabel(template)]
        except KeyError as e:
            raise ConfigurationError(
                f"Cert spec '{name}' refers to '{template}' as a "
                f"template, but '{template}' hasn't been declared yet."
            ) from e
        effective_cert_config = dict(template_spec.templatable_config)
        template_extensions = effective_cert_config.get('extensions', [])
        effective_cert_config.update(cert_config)

        # add new extensions
        effective_cert_config['extensions'] = _combine_extension_cfgs(
            extensions,
            template_extensions,
            effective_cert_config.get('unique_extensions', True),
        )
    else:
        effective_cert_config = dict(cert_config)

    # derive templatable config before setting defaults
    effective_cert_config['templatable_config'] = dict(
        CertificateSpec.extract_templatable_config(effective_cert_config)
    )
    return effective_cert_config


def _process_single_cert_spec(
    state: _CertSpecConfigState,
    name,
    cert_config,
    config_search_dir,
    cert_cache,
):
    name = CertLabel(name)
    cert_config = key_dashes_to_underscores(cert_config)

    effective_cert_config = _process_template_config(
        state.cert_specs, name, cert_config
    )

    effective_cert_config['label'] = name.value
    effective_cert_config.setdefault('subject', name.value)
    effective_cert_config.setdefault(
        'subject_key', effective_cert_config['subject']
    )
    _config_issuer_serial(state, name, effective_cert_config)

    state.cert_specs[name] = spec = CertificateSpec.from_config(
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
    state.cert_labels_by_issuer[spec.issuer].append(name)
    state.cert_labels_by_subject[spec.subject].append(name)


def _process_cert_spec_settings(
    cert_spec_config, config_search_dir, cert_cache
):
    state = _CertSpecConfigState()
    for name, cert_config in cert_spec_config.items():
        _process_single_cert_spec(
            state, name, cert_config, config_search_dir, cert_cache
        )

    return (
        state.cert_specs,
        state.cert_labels_by_issuer,
        state.cert_labels_by_subject,
    )


@dataclass(frozen=True)
class _ACSpecConfigState(_IssuedItemConfigState):

    cert_labels_by_holder: Dict[EntityLabel, List[CertLabel]] = field(
        default_factory=lambda: defaultdict(list)
    )
    ac_specs: Dict[CertLabel, AttributeCertificateSpec] = field(
        default_factory=dict
    )


def _process_ac_spec_config(ac_spec_config):
    state = _ACSpecConfigState()
    for name, ac_config in ac_spec_config.items():
        name = CertLabel(name)
        ac_config = key_dashes_to_underscores(ac_config)
        effective_cert_config = dict(ac_config)

        effective_cert_config['label'] = name.value
        _config_issuer_serial(state, name, effective_cert_config)

        if effective_cert_config.get('unique_extensions', True):
            effective_cert_config['extensions'] = _combine_extension_cfgs(
                effective_cert_config.get('extensions', []), [], True
            )

        state.ac_specs[name] = spec = AttributeCertificateSpec.from_config(
            effective_cert_config
        )
        state.cert_labels_by_issuer[spec.issuer].append(name)
        state.cert_labels_by_holder[spec.holder.name].append(name)

    return (
        state.ac_specs,
        state.cert_labels_by_issuer,
        state.cert_labels_by_holder,
    )


DEFAULT_FIRST_SERIAL = 0x1000


class PKIArchitecture:
    """
    A collection of entities, keys, certificates and trust services, as
    modelled by Certomancer.
    """

    # These config keys will be merged when an architecture is templated
    MULTIVAL_CONFIG_KEYS = (
        'entities',
        'certs',
        'entity-defaults',
        'attr-certs',
    )
    CONFIG_KEYS = ('keyset', 'services', *MULTIVAL_CONFIG_KEYS)

    @classmethod
    def build_architecture(
        cls,
        arch_label: ArchLabel,
        cfg: dict,
        key_sets: KeySets,
        external_url_prefix,
        extension_plugins: ExtensionPluginRegistry = None,
        service_plugins: 'ServicePluginRegistry' = None,
        config_search_dir: Optional[SearchDir] = None,
        cert_cache=None,
        ac_cache=None,
    ) -> 'PKIArchitecture':
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
        entities = EntityRegistry(entity_cfg, cfg.get('entity-defaults', None))
        services = cfg.get('services', {})
        return PKIArchitecture(
            arch_label,
            key_set=key_set,
            entities=entities,
            cert_spec_config=cert_specs,
            service_config=services,
            external_url_prefix=external_url_prefix,
            extension_plugins=extension_plugins,
            config_search_dir=config_search_dir,
            service_plugins=service_plugins,
            ac_spec_config=ac_specs,
            cert_cache=cert_cache,
            ac_cache=ac_cache,
        )

    @classmethod
    def build_architectures(
        cls,
        key_sets: KeySets,
        cfgs: Dict[str, Any],
        external_url_prefix: str,
        config_search_dir: Optional[SearchDir],
        extension_plugins: ExtensionPluginRegistry = None,
        service_plugins: 'ServicePluginRegistry' = None,
    ):
        arch_specs: Dict[ArchLabel, Dict[str, Any]] = {}
        for lbl, cfg in cfgs.items():
            arch_label = ArchLabel(lbl)
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
                arch_label=arch_label,
                cfg=cfg,
                key_sets=key_sets,
                external_url_prefix=external_url_prefix,
                extension_plugins=extension_plugins,
                config_search_dir=config_search_dir,
                service_plugins=service_plugins,
            )

    def __init__(
        self,
        arch_label: ArchLabel,
        key_set: KeySet,
        entities: EntityRegistry,
        cert_spec_config,
        service_config,
        external_url_prefix,
        ac_spec_config=None,
        extension_plugins: ExtensionPluginRegistry = None,
        attr_plugins: AttributePluginRegistry = None,
        service_plugins: ServicePluginRegistry = None,
        profile_plugins: CertProfilePluginRegistry = None,
        config_search_dir: Optional[SearchDir] = None,
        cert_cache=None,
        ac_cache=None,
    ):

        self.arch_label = arch_label
        self.key_set = key_set
        self.entities = entities

        self.extn_plugin_registry = (
            extension_plugins or plugin_api.extension_plugin_registry
        )
        self.attr_plugin_registry = (
            attr_plugins or plugin_api.attr_plugin_registry
        )

        self.profile_registry: CertProfilePluginRegistry = (
            profile_plugins or cert_profile_plugin_registry
        )

        self.service_registry: ServiceRegistry = ServiceRegistry(
            self, external_url_prefix, service_config, plugins=service_plugins
        )

        # Parse certificate specs
        # This only processes the configuration, the actual signing etc.
        # happens on-demand
        cert_specs: Dict[CertLabel, CertificateSpec] = {}
        self._cert_specs = cert_specs

        cert_cache = cert_cache if cert_cache is not None else {}
        ac_cache = ac_cache if ac_cache is not None else {}
        (
            self._cert_specs,
            cert_labels_by_issuer,
            cert_labels_by_subject,
        ) = _process_cert_spec_settings(
            cert_spec_config, config_search_dir, cert_cache
        )
        (
            self._ac_specs,
            ac_labels_by_issuer,
            ac_labels_by_holder,
        ) = _process_ac_spec_config(ac_spec_config or {})
        self._cert_labels_by_issuer: Dict[
            EntityLabel, List[CertLabel]
        ] = cert_labels_by_issuer
        self._cert_labels_by_subject: Dict[
            EntityLabel, List[CertLabel]
        ] = cert_labels_by_subject
        self._ac_labels_by_issuer: Dict[
            EntityLabel, List[CertLabel]
        ] = ac_labels_by_issuer
        self._ac_labels_by_holder: Dict[
            EntityLabel, List[CertLabel]
        ] = ac_labels_by_holder
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

    def find_cert_label(
        self,
        cid: ocsp.CertId,
        issuer_label: Optional[EntityLabel] = None,
        is_ac=False,
    ) -> CertLabel:
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
                    lbl
                    for lbl in by_iss_map.keys()
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
            return next(lbl for lbl in specs if _lbl_to_serial(lbl) == serial)
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

    def enumerate_certs_by_issuer(
        self,
    ) -> Iterable[Tuple[EntityLabel, Iterable[CertificateSpec]]]:
        for iss_label, issd_certs in self._cert_labels_by_issuer.items():
            yield iss_label, map(self.get_cert_spec, issd_certs)

    def enumerate_attr_certs_by_issuer(
        self,
    ) -> Iterable[Tuple[EntityLabel, Iterable[AttributeCertificateSpec]]]:
        for iss_label, issd_certs in self._ac_labels_by_issuer.items():
            yield iss_label, map(self.get_attr_cert_spec, issd_certs)

    def enumerate_attr_certs_of_holder(
        self, holder_name: EntityLabel, issuer: Optional[EntityLabel] = None
    ):
        relevant: Iterable[CertLabel]
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

    def package_pkcs12(
        self,
        cert_label: CertLabel,
        key_label: KeyLabel = None,
        certs_to_embed: Iterable[CertLabel] = None,
        password: bytes = None,
    ):
        try:
            from cryptography import x509 as pyca_x509
            from cryptography.hazmat.primitives.asymmetric import (
                dsa,
                ec,
                ed448,
                ed25519,
                rsa,
            )
            from cryptography.hazmat.primitives.serialization import (
                BestAvailableEncryption,
                NoEncryption,
                load_der_private_key,
                pkcs12,
            )
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
        assert isinstance(
            key,
            (
                rsa.RSAPrivateKey,
                dsa.DSAPrivateKey,
                ec.EllipticCurvePrivateKey,
                ed25519.Ed25519PrivateKey,
                ed448.Ed448PrivateKey,
            ),
        )
        chain = [pyca_x509.load_der_x509_certificate(c) for c in chain_der]

        encryption_alg: KeySerializationEncryption
        if not password:
            encryption_alg = NoEncryption()
        else:
            encryption_alg = BestAvailableEncryption(password)

        return pkcs12.serialize_key_and_certificates(
            name=None,
            key=key,
            cert=cert,
            cas=chain,
            encryption_algorithm=encryption_alg,
        )

    def is_subject_key_available(self, cert: CertLabel):
        key_label = self.get_cert_spec(cert).subject_key
        key_pair = self.key_set.get_asym_key(key_label)
        return key_pair.private is not None

    def _dump_certs(
        self, use_pem=True, flat=False, include_pkcs12=False, pkcs12_pass=None
    ):
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

    def dump_certs(
        self,
        folder_path: str,
        use_pem=True,
        flat=False,
        include_pkcs12=False,
        pkcs12_pass=None,
    ):
        os.makedirs(folder_path, exist_ok=True)
        self._load_all_certs()
        itr_certs = self._dump_certs(
            use_pem=use_pem,
            flat=flat,
            include_pkcs12=include_pkcs12,
            pkcs12_pass=pkcs12_pass,
        )
        itr_att_certs = self._dump_attr_certs(use_pem=use_pem, flat=flat)
        for name, data in itertools.chain(itr_certs, itr_att_certs):
            path = os.path.join(folder_path, name)
            if data is None:  # folder
                os.makedirs(path, exist_ok=True)
            else:
                with open(path, 'wb') as f:
                    f.write(data)

    def zip_certs(
        self,
        output_buffer,
        use_pem=True,
        flat=False,
        include_pkcs12=False,
        pkcs12_pass=None,
    ):
        zip_file = ZipFile(output_buffer, 'w')
        lbl = self.arch_label.value
        itr = self._dump_certs(
            use_pem=use_pem,
            flat=flat,
            include_pkcs12=include_pkcs12,
            pkcs12_pass=pkcs12_pass,
        )
        for name, data in itr:
            if data is None:
                continue
            fname = os.path.join(lbl, name)
            zip_file.writestr(fname, data)
        zip_file.close()

    def _collect_extensions(
        self, spec: IssuedItemSpec, extension_dict: Dict[str, x509.Extension]
    ) -> List[x509.Extension]:

        if spec.unique_extensions:
            # apply profiles
            exts_from_profile = self.profile_registry.apply_profiles(
                arch=self, item_spec=spec
            )
            extension_dict.update(
                {
                    k: ext_spec.to_asn1(self, x509.Extension)
                    for k, ext_spec in exts_from_profile.items()
                }
            )
            # add extensions from config
            extension_dict.update(
                {
                    ext_spec.id: ext_spec.to_asn1(self, x509.Extension)
                    for ext_spec in spec.extensions
                }
            )
            extensions = list(extension_dict.values())
        else:
            # no profiles in non-unique mode
            extensions = list(extension_dict.values())
            extensions.extend(
                ext_spec.to_asn1(self, x509.Extension)
                for ext_spec in spec.extensions
            )
        return extensions

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
            digest_algo, authority_key.public_key_info, signature_algo
        )

        try:
            issuer_cert_lbl = spec.resolve_issuer_cert(self)
            issuer_cert = self.get_cert(issuer_cert_lbl)
            aki = issuer_cert.key_identifier_value
        except CertomancerServiceError:
            aki = None

        if aki is None:
            aki = authority_key.public_key_info.sha1

        aki_value = x509.AuthorityKeyIdentifier({'key_identifier': aki})
        aki_extension = x509.Extension(
            {
                'extn_id': 'authority_key_identifier',
                'critical': False,
                'extn_value': aki_value,
            }
        )
        extension_dict = {'authority_key_identifier': aki_extension}
        extensions = self._collect_extensions(spec, extension_dict)

        attributes = [attr.to_asn1(self) for attr in spec.attributes]
        tbs = cms.AttributeCertificateInfoV2(
            {
                'version': 'v2',
                'holder': spec.holder.to_asn1(self),
                'issuer': cms.AttCertIssuer(
                    name='v2_form',
                    value=cms.V2Form(
                        {'issuer_name': [as_general_name(issuer_name)]}
                    ),
                ),
                'signature': signature_algo_obj,
                'serial_number': spec.serial,
                'att_cert_validity_period': spec.validity.att_asn1,
                'attributes': attributes,
                'extensions': extensions,
            }
        )

        signature = generic_sign(
            private_key=authority_key.private_key_info,
            tbs_bytes=tbs.dump(),
            signature_algo=signature_algo_obj,
        )

        cert = cms.AttributeCertificateV2(
            {
                'ac_info': tbs,
                'signature_algorithm': signature_algo_obj,
                'signature': signature,
            }
        )

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
            digest_algo, authority_key.public_key_info, signature_algo
        )

        # SKI and AKI are required by RFC 5280 in (almost) all certificates
        # so we include them here
        # TODO check for potential duplication?
        ski = subject_key.public_key_info.sha1
        ski_extension = x509.Extension(
            {
                'extn_id': 'key_identifier',
                'critical': False,
                'extn_value': core.OctetString(ski),
            }
        )
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
                aki = None

        if aki is None:
            # use SHA-1 hash of issuer's public key as the default
            # AKI value (which should be equivalent to the above, unless
            # the user loaded in certificates that weren't generated
            # by Certomancer)
            aki = authority_key.public_key_info.sha1

        aki_value = x509.AuthorityKeyIdentifier({'key_identifier': aki})
        aki_extension = x509.Extension(
            {
                'extn_id': 'authority_key_identifier',
                'critical': False,
                'extn_value': aki_value,
            }
        )
        extensions = self._collect_extensions(
            spec,
            {
                'key_identifier': ski_extension,
                'authority_key_identifier': aki_extension,
            },
        )
        tbs = x509.TbsCertificate(
            {
                'version': 'v3',
                'serial_number': spec.serial,
                'signature': signature_algo_obj,
                'issuer': issuer_name,
                'validity': spec.validity.asn1,
                'subject': subject_name,
                'subject_public_key_info': subject_key.public_key_info,
                'extensions': extensions,
            }
        )
        tbs_bytes = tbs.dump()
        signature = generic_sign(
            private_key=authority_key.private_key_info,
            tbs_bytes=tbs_bytes,
            signature_algo=signature_algo_obj,
        )

        cert = x509.Certificate(
            {
                'tbs_certificate': tbs,
                'signature_algorithm': signature_algo_obj,
                'signature_value': signature,
            }
        )

        self._cert_cache[label] = cert
        return cert

    def check_revocation_status(
        self, cert_label, at_time: datetime, is_ac=False
    ) -> Optional[RevocationStatus]:
        spec = (
            self.get_attr_cert_spec(cert_label)
            if is_ac
            else self.get_cert_spec(cert_label)
        )
        revo = spec.revocation
        if revo is not None and revo.revoked_since <= at_time:
            return revo
        else:
            return None

    def get_cert_labels_for_entity(
        self, entity_label: EntityLabel
    ) -> List[CertLabel]:
        return self._cert_labels_by_subject[entity_label]

    def get_unique_cert_for_entity(
        self, entity_label: EntityLabel
    ) -> CertLabel:
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

    def get_revoked_certs_at_time(
        self, issuer_label: EntityLabel, at_time: datetime
    ):
        labels = self._cert_labels_by_issuer[issuer_label]
        for cert_label in labels:
            revo = self.check_revocation_status(cert_label, at_time=at_time)
            cert = self.get_cert(cert_label)
            if revo is not None:
                yield self._format_revo(cert.serial_number, revo)

    def get_revoked_attr_certs_at_time(
        self, issuer_label: EntityLabel, at_time: datetime
    ):
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


class ServiceRegistry:
    """
    Dispatcher class to interact with services associated with a PKI
    architecture.
    """

    def __init__(
        self,
        pki_arch: PKIArchitecture,
        external_url_prefix,
        service_config,
        plugins: ServicePluginRegistry = None,
    ):
        self.pki_arch = pki_arch
        self.plugins = plugins or plugin_api.service_plugin_registry

        def _gen_svc_config(configs):
            for lbl, cfg in configs.items():
                cfg = dict(cfg)
                cfg.setdefault('external-url-prefix', external_url_prefix)
                cfg['label'] = lbl
                cfg['arch_label'] = pki_arch.arch_label.value
                yield ServiceLabel(lbl), cfg

        check_config_keys(
            'services',
            (
                'ocsp',
                'crl-repo',
                'cert-repo',
                'attr-cert-repo',
                'time-stamping',
                'plugin',
            ),
            service_config,
        )

        self._ocsp = {
            label: OCSPResponderServiceInfo.from_config(cfg)
            for label, cfg in _gen_svc_config(service_config.get('ocsp', {}))
        }
        self._crl_repo = {
            label: CRLRepoServiceInfo.from_config(cfg)
            for label, cfg in _gen_svc_config(
                service_config.get('crl-repo', {})
            )
        }
        self._cert_repo = {
            label: CertRepoServiceInfo.from_config(cfg)
            for label, cfg in _gen_svc_config(
                service_config.get('cert-repo', {})
            )
        }
        self._attr_cert_repo = {
            label: AttrCertRepoServiceInfo.from_config(cfg)
            for label, cfg in _gen_svc_config(
                service_config.get('attr-cert-repo', {})
            )
        }
        self._tsa = {
            label: TSAServiceInfo.from_config(cfg)
            for label, cfg in _gen_svc_config(
                service_config.get('time-stamping', {})
            )
        }

        plugin_cfg = service_config.get('plugin', {})

        # TODO type checks with better error reporting

        def _cfg_plugin(plugin_label, cfg_for_plugin):
            plugin = self.plugins[plugin_label]
            content_type = plugin.content_type
            svc_configs = _gen_svc_config(cfg_for_plugin)
            for service_label, cfg in svc_configs:
                yield service_label, PluginServiceInfo(
                    plugin_label=plugin_label,
                    content_type=content_type,
                    plugin_config=plugin.process_plugin_config(cfg),
                    label=service_label,
                    external_url_prefix=cfg['external-url-prefix'],
                    arch_label=pki_arch.arch_label,
                )

        self._plugin_services = {
            PluginLabel(plugin_label): dict(
                _cfg_plugin(PluginLabel(plugin_label), cfg)
            )
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

    def summon_responder(
        self, label: ServiceLabel, at_time=None
    ) -> SimpleOCSPResponder:
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
                info.digest_algo,
                responder_cert.public_key,
                signature_algo=info.signature_algo,
            ),
            at_time=at_time,
            revinfo_interface=OCSPInterface(
                for_issuer=info.for_issuer,
                pki_arch=self.pki_arch,
                issuer_cert_label=issuer_cert_label,
                is_aa_responder=info.is_aa_responder,
            ),
            response_extensions=extra_extensions,
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

    def get_attr_cert_repo_info(
        self, label: ServiceLabel
    ) -> AttrCertRepoServiceInfo:
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

    def summon_timestamper(
        self, label: ServiceLabel, at_time=None
    ) -> TimeStamper:
        # TODO allow policy parameter to be customised
        info = self.get_tsa_info(label)
        tsa_key = self.pki_arch.key_set.get_private_key(info.signing_key)
        tsa_cert = self.pki_arch.get_cert(info.signing_cert)
        return TimeStamper(
            tsa_cert=tsa_cert,
            tsa_key=tsa_key,
            fixed_dt=at_time,
            signature_algo=choose_signed_digest(
                info.digest_algo,
                pub_key=tsa_cert.public_key,
                signature_algo=info.signature_algo,
            ),
            certs_to_embed=[
                self.pki_arch.get_cert(lbl) for lbl in info.certs_to_embed
            ],
            md_algorithm=info.digest_algo,
        )

    def get_crl(
        self,
        repo_label: ServiceLabel,
        at_time: Optional[datetime] = None,
        number: Optional[int] = None,
    ):
        # TODO support indirect CRLs, delta CRLs, etc.?

        crl_info = self.get_crl_repo_info(repo_label)
        issuer_cert_label = crl_info.issuer_cert
        signing_key_pair = self.pki_arch.key_set.get_asym_key(
            crl_info.signing_key
        )
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
                crl_info.digest_algo,
                signing_key_pair.public,
                signature_algo=crl_info.signature_algo,
            ),
            authority_key_identifier=iss_cert.key_identifier_value,
            extra_crl_extensions=extra_extensions,
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
            crl_number=number,
            this_update=this_update,
            next_update=next_update,
            revoked_certs=revoked,
            distpoint=crl_info.format_idp(),
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

    def _check_repo_membership(
        self,
        repo_info: BaseCertRepoServiceInfo,
        cert_label: CertLabel,
        is_attr=False,
    ):
        # check if the cert in question actually belongs to the repo
        # (i.e. whether it is issued by the right entity)
        cert_spec: IssuedItemSpec
        if is_attr:
            cert_spec = self.pki_arch.get_attr_cert_spec(cert_label)
        else:
            cert_spec = self.pki_arch.get_cert_spec(cert_label)

        return cert_spec.issuer == repo_info.for_issuer

    def get_cert_from_repo(
        self, repo_label: ServiceLabel, cert_label: Optional[CertLabel] = None
    ) -> Optional[x509.Certificate]:

        repo_info = self.get_cert_repo_info(repo_label)
        arch = self.pki_arch
        if cert_label is None:
            cert_label = self.determine_repo_issuer_cert(repo_info)
        elif not self._check_repo_membership(repo_info, cert_label):
            return None
        return arch.get_cert(cert_label)

    def get_attr_cert_from_repo(
        self, repo_label: ServiceLabel, cert_label: CertLabel
    ) -> Optional[cms.AttributeCertificateV2]:

        repo_info = self.get_attr_cert_repo_info(repo_label)
        if not self._check_repo_membership(repo_info, cert_label, is_attr=True):
            return None
        return self.pki_arch.get_attr_cert(cert_label)

    def invoke_plugin(
        self,
        plugin_label: PluginLabel,
        label: ServiceLabel,
        request: bytes,
        at_time: Optional[datetime] = None,
    ) -> bytes:
        info = self.get_plugin_info(plugin_label, label)
        return self.plugins.invoke_plugin(
            self.pki_arch, info, request, at_time=at_time
        )

    def get_plugin_info(
        self, plugin_label: PluginLabel, label: ServiceLabel
    ) -> PluginServiceInfo:
        self.plugins.assert_registered(plugin_label)
        try:
            svcs_for_plugin = self._plugin_services.get(plugin_label, {})
            return svcs_for_plugin[label]
        except KeyError as e:
            raise ConfigurationError(
                f"The plugin-service combination '{plugin_label}'-'{label}' "
                f"does not exist."
            ) from e

    def list_plugin_services(
        self, plugin_label: Optional[PluginLabel] = None
    ) -> List[PluginServiceInfo]:
        svcs = self._plugin_services

        def _enumerate_svcs(*relevant_plugins):
            for plg in relevant_plugins:
                yield from svcs[plg].values()

        if plugin_label is not None:
            self.plugins.assert_registered(plugin_label)
            return list(_enumerate_svcs(plugin_label))
        else:
            return list(_enumerate_svcs(*svcs.keys()))
