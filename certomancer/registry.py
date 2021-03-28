import abc
import os
import os.path
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional, List

import yaml
from dateutil.parser import parse as parse_dt
from asn1crypto import x509, core, pem, ocsp
from dateutil.tz import tzlocal
from oscrypto import keys as oskeys, asymmetric
from asn1crypto.keys import PrivateKeyInfo, PublicKeyInfo

from .config_utils import ConfigurationError, check_config_keys, \
    ConfigurableMixin, parse_duration, key_dashes_to_underscores, get_and_apply
from .services import CertomancerServiceError, generic_sign, CRLBuilder, \
    issuer_match, choose_signed_digest, SimpleOCSPResponder, TimeStamper, \
    RevocationInfoInterface, RevocationStatus


@dataclass(frozen=True)
class AsymKey:
    public: PublicKeyInfo
    private: Optional[PrivateKeyInfo] = None

    @property
    def algorithm(self):
        return self.public.algorithm


class KeyFromFile:

    def __init__(self, name: str, path: str, public_only: bool = False,
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
                public = oskeys.parse_public(key_bytes)
                private = None
            else:
                private = oskeys.parse_private(
                    key_bytes, password=self.password
                )
                public = asymmetric.load_private_key(private).public_key.asn1
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
    def __init__(self, config, lazy_load_keys=False):
        check_config_keys('KeySet', ('path-prefix', 'keys'), config)
        try:
            keys = config['keys']
        except KeyError as e:
            raise ConfigurationError(
                "The 'keys' entry is mandatory in all key sets"
            ) from e
        path_prefix = config.get('path-prefix', '')
        if path_prefix and not path_prefix.endswith('/'):
            path_prefix += '/'

        # apply path prefix to key configs
        def _prepend(key_conf):
            try:
                key_conf['path'] = path_prefix + key_conf['path']
            except KeyError:
                pass
            return key_conf

        self._dict = {
            k: KeyFromFile.from_config(
                k, _prepend(v), lazy=lazy_load_keys
            )
            for k, v in keys.items()
        }

    def __getitem__(self, name) -> KeyFromFile:
        try:
            return self._dict[name]
        except KeyError as e:
            raise ConfigurationError(
                f"There is no key labelled '{name}'."
            ) from e

    def retrieve_asym_key(self, name) -> AsymKey:
        return self[name].key_pair

    def get_public_key(self, name) -> PublicKeyInfo:
        return self[name].public_key_info

    def get_private_key(self, name) -> PrivateKeyInfo:
        pki = self[name].private_key_info
        if pki is None:
            raise ConfigurationError(
                f"Key '{name}' does not have an associated private key."
            )
        return pki


class KeySets:
    def __init__(self, config, lazy_load_keys=False):
        self._dict = {
            k: KeySet(v, lazy_load_keys=lazy_load_keys)
            for k, v in config.items()
        }

    def __getitem__(self, name) -> KeySet:
        try:
            return self._dict[name]
        except KeyError as e:
            raise ConfigurationError(
                f"There is no registered key set labelled '{name}'."
            ) from e


class EntityRegistry:
    def __init__(self, config):
        self._dict = {
            k: x509.Name.build(key_dashes_to_underscores(v))
            for k, v in config.items()
        }

    def __getitem__(self, name) -> x509.Name:
        try:
            return self._dict[name]
        except KeyError as e:
            raise ConfigurationError(
                f"There is no registered entity labelled '{name}'."
            ) from e


@dataclass(frozen=True)
class Validity(ConfigurableMixin):
    valid_from: datetime
    valid_to: datetime

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


class SmartValueProcessor(abc.ABC):
    def provision(self, arch: 'PKIArchitecture', params):
        raise NotImplementedError


@dataclass(frozen=True)
class SmartValueSpec(ConfigurableMixin):
    schema: str
    params: dict = field(default_factory=dict)


class SmartValueProcessorRegistry:
    def __init__(self, arch: 'PKIArchitecture'):
        self.arch = arch
        self._dict = {}

    def register(self, schema_label: str, processor: SmartValueProcessor):
        self._dict[schema_label] = processor

    def process_value(self, spec: SmartValueSpec):
        try:
            proc: SmartValueProcessor = self._dict[spec.schema]
        except KeyError as e:
            raise ConfigurationError(
                f"There is no registered processor for the schema "
                f"'{spec.schema}'."
            ) from e
        return proc.provision(self.arch, spec.params)


@dataclass(frozen=True)
class ExtensionSpec(ConfigurableMixin):
    id: str
    critical: bool = False
    value: object = None
    smart_value: Optional[SmartValueSpec] = None

    @classmethod
    def process_entries(cls, config_dict):
        try:
            ext_id = config_dict['id']
        except KeyError as e:
            raise ConfigurationError(
                "'id' entry is mandatory for all extensions"
            ) from e

        sv_spec = config_dict.get('smart_value', None)
        value = config_dict.get('value', None)
        if sv_spec is not None and value is not None:
            raise ConfigurationError(
                f"Cannot specify both smart-value and value on a certificate "
                f"extension. At least one {ext_id} extension does not "
                f"meet this criterion."
            )
        elif sv_spec is not None:
            config_dict['smart_value'] = SmartValueSpec.from_config(sv_spec)
        elif value is not None and isinstance(value, dict):
            # asn1crypto compatibility
            config_dict['value'] = {
                k.replace('-', '_'): v for k, v in value.items()
            }
        super().process_entries(config_dict)

    def to_asn1(self, proc_registry: SmartValueProcessorRegistry) \
            -> x509.Extension:
        value = self.value
        if value is None and self.smart_value is not None:
            value = proc_registry.process_value(self.smart_value)

        return x509.Extension({
            'extn_id': x509.ExtensionId(self.id),
            'critical': self.critical,
            'extn_value': value
        })


EXCLUDED_FROM_TEMPLATE = frozenset({'subject', 'subject_key'})


@dataclass(frozen=True)
class CertificateSpec(ConfigurableMixin):
    subject: str
    subject_key: str
    issuer: str
    authority_key: str
    validity: Validity
    _templatable_config: dict
    signature_algo: Optional[str] = None
    digest_algo: str = 'sha256'
    revocation: Optional[RevocationStatus] = None
    extensions: List[ExtensionSpec] = field(default_factory=list)

    @property
    def self_issued(self) -> bool:
        return self.subject == self.issuer

    @property
    def self_signed(self) -> bool:
        return self.subject_key == self.authority_key

    @classmethod
    def process_entries(cls, config_dict):
        try:
            val_spec = config_dict['validity']
            config_dict['validity'] = Validity.from_config(val_spec)
        except KeyError:
            pass

        revocation = config_dict.get('revocation', None)
        if revocation is not None:
            config_dict['revocation'] = RevocationStatus.from_config(revocation)

        try:
            ext_spec = config_dict['extensions']
            if not isinstance(ext_spec, list):
                raise ConfigurationError(
                    "Applicable certificate extensions must be specified"
                    "as a list."
                )
        except KeyError:
            ext_spec = ()

        config_dict['extensions'] = [
            ExtensionSpec.from_config(ext_cfg) for ext_cfg in ext_spec
        ]

        super().process_entries(config_dict)

    @classmethod
    def from_config(cls, config_dict) -> 'CertificateSpec':
        if not isinstance(config_dict, dict):
            raise ConfigurationError(
                f"Cert config should be a dictionary, not {type(config_dict)}."
            )
        # Do this first for consistency, so we don't put processed values
        # into the template
        config_dict['_templatable_config'] = {
            k: v for k, v in config_dict.items()
            if k not in EXCLUDED_FROM_TEMPLATE
        }
        return super().from_config(config_dict)


DEFAULT_FIRST_SERIAL = 0x1001


class PKIArchitecture:
    @classmethod
    def default_smart_value_procs(cls):
        from .smart_values import (
            AIAUrlProc, CRLDistributionPointsProc, KeyUsageProc
        )
        return {
            AIAUrlProc.schema_label: AIAUrlProc(),
            CRLDistributionPointsProc.schema_label: CRLDistributionPointsProc(),
            KeyUsageProc.schema_label: KeyUsageProc()
        }

    @classmethod
    def build_architectures(cls, key_sets: KeySets, cfgs, global_base_url,
                            smart_value_procs=None):
        if smart_value_procs is None:
            smart_value_procs = cls.default_smart_value_procs()
        for arch_label, cfg in cfgs.items():
            check_config_keys(
                arch_label, ('keyset', 'entities', 'certs', 'services'),
                cfg
            )
            service_base_url = cfg.get(
                'base-url', f"{global_base_url}/{arch_label}"
            )
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
            entities = EntityRegistry(entity_cfg)
            services = cfg.get('services', {})
            yield PKIArchitecture(
                arch_label, key_set=key_set, entities=entities,
                cert_spec_config=cert_specs,
                service_config=services, service_base_url=service_base_url,
                smart_value_procs=smart_value_procs
            )

    def __init__(self, arch_label: str,
                 key_set: KeySet, entities: EntityRegistry,
                 cert_spec_config, service_config, service_base_url,
                 smart_value_procs):
        self.arch_label = arch_label
        self.key_set = key_set
        self.entities = entities

        # register smart value processors
        if smart_value_procs is None:
            smart_value_procs = self.__class__.default_smart_value_procs()
        self.proc_registry = pr = SmartValueProcessorRegistry(self)
        for schema, proc in smart_value_procs.items():
            pr.register(schema, proc)

        self._serial_by_issuer = defaultdict(lambda: DEFAULT_FIRST_SERIAL)

        self.service_registry = ServiceRegistry(
            self, service_base_url, service_config
        )

        # Parse certificate specs
        # This only processes the configuration, the actual signing etc.
        # happens on-demand
        self._cert_specs = cert_specs = {}
        self._labels_by_issuer = defaultdict(list)
        for name, cert_config in cert_spec_config.items():
            cert_config = key_dashes_to_underscores(cert_config)
            template = cert_config.pop('template', None)
            if template is not None:
                try:
                    template_spec: CertificateSpec = cert_specs[template]
                except KeyError as e:
                    raise ConfigurationError(
                        f"Cert spec '{name}' refers to '{template}' as a "
                        f"template, but '{template}' hasn't been declared yet."
                    ) from e
                effective_cert_config = dict(template_spec._templatable_config)
                effective_cert_config.update(cert_config)
            else:
                effective_cert_config = dict(cert_config)

            effective_cert_config.setdefault('subject', name)
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

            cert_specs[name] = spec = CertificateSpec.from_config(
                effective_cert_config
            )
            self._labels_by_issuer[spec.issuer].append(name)

        self._cert_cache = {}

    def get_cert_spec(self, label) -> CertificateSpec:
        try:
            return self._cert_specs[label]
        except KeyError as e:
            raise ConfigurationError(
                f"There is no registered certificate labelled '{label}'."
            ) from e

    def find_cert_label(self, cid: ocsp.CertId, issuer_label=None) -> str:
        # FIXME this doesn't really scale
        serial = cid['serial_number'].native
        if issuer_label is None:
            try:
                issuer_label = next(
                    lbl for lbl in self._labels_by_issuer.keys()
                    # we could go via entities, but this way is safer
                    if issuer_match(cid, self.get_cert(lbl))
                )
            except StopIteration as e:
                raise CertomancerServiceError(
                    f"Could not find a suitable issuer for CertID {cid.native}."
                ) from e

        specs = self._labels_by_issuer[issuer_label]
        try:
            return next(
                lbl for lbl in specs
                if self.get_cert(lbl).serial_number == serial
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

    def dump_certs(self, folder_path: str, use_pem=True):
        self._load_all_certs()

        # start writing only after we know that all certs have been built
        ext = '.cert.pem' if use_pem else '.crt'
        for iss_label, iss_certs in self._labels_by_issuer.items():
            iss_path = os.path.join(folder_path, iss_label)
            os.makedirs(iss_path, exist_ok=True)
            for cert_label in iss_certs:
                cert = self.get_cert(cert_label)
                with open(os.path.join(iss_path, cert_label + ext), 'wb') as f:
                    data = cert.dump()
                    if use_pem:
                        data = pem.armor('certificate', data)
                    f.write(data)

    def get_cert(self, label) -> x509.Certificate:
        try:
            return self._cert_cache[label]
        except KeyError:
            pass

        spec = self.get_cert_spec(label)
        subject_name = self.entities[spec.subject]
        subject_key = self.key_set[spec.subject]
        issuer_name = self.entities[spec.issuer]
        authority_key = self.key_set[spec.authority_key]
        serial = self._serial_by_issuer[spec.issuer]

        signature_algo = spec.signature_algo
        digest_algo = spec.digest_algo
        signature_algo_obj = choose_signed_digest(
            digest_algo, authority_key.public_key_info.algorithm,
            signature_algo
        )

        # SKI and AKI are required by RFC 5280 in (almost) all certificates
        # so we include them here
        # TODO check for potential duplication?
        ski = subject_key.public_key_info.sha1
        ski_extension = x509.Extension({
            'extn_id': 'key_identifier',
            'critical': False,
            'extn_value': core.ParsableOctetString(core.OctetString(ski).dump())
        })
        aki_value = x509.AuthorityKeyIdentifier({
            'key_identifier': (
                ski if spec.self_signed
                else self.get_cert(spec.issuer).key_identifier_value
            )
        })
        aki_extension = x509.Extension({
            'extn_id': 'authority_key_identifier',
            'critical': False,
            'extn_value': core.ParsableOctetString(aki_value.dump())
        })
        extensions = [ski_extension, aki_extension]
        # add extensions from config
        extensions.extend(
            ext_spec.to_asn1(self.proc_registry) for ext_spec in spec.extensions
        )
        tbs = x509.TbsCertificate({
            'version': 'v3',
            'serial_number': serial,
            'signature': signature_algo_obj,
            'issuer': issuer_name,
            'validity': x509.Validity({
                'not_before': x509.Time(
                    {'general_time': spec.validity.valid_from}
                ),
                'not_after': x509.Time(
                    {'general_time': spec.validity.valid_to}
                ),
            }),
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

        self._serial_by_issuer[spec.issuer] = serial + 1
        self._cert_cache[label] = cert
        return cert

    def check_revocation_status(self, cert_label, at_time: datetime) \
            -> Optional[RevocationStatus]:
        spec = self.get_cert_spec(cert_label)
        revo = spec.revocation
        if revo is not None and revo.revoked_since <= at_time:
            return revo
        else:
            return None

    def get_revoked_certs_at_time(self, issuer_label: str, at_time: datetime):
        labels = self._labels_by_issuer[issuer_label]
        for cert_label in labels:
            revo = self.check_revocation_status(cert_label, at_time=at_time)
            cert = self.get_cert(cert_label)
            if revo is not None:
                yield revo.to_asn1(cert.serial_number)


@dataclass(frozen=True)
class ServiceInfo(ConfigurableMixin):
    label: str
    base_url: str


@dataclass(frozen=True)
class OCSPResponderServiceInfo(ServiceInfo):
    for_issuer: str
    responder_cert: str
    signing_key: str = None
    signature_algo: Optional[str] = None
    digest_algo: str = 'sha256'

    @classmethod
    def process_entries(cls, config_dict):
        try:
            config_dict.setdefault('signing_key', config_dict['responder_cert'])
        except KeyError:
            pass

    @property
    def url(self):
        return f"{self.base_url}/{self.label}"


@dataclass(frozen=True)
class TSAServiceInfo(ServiceInfo):
    signing_cert: str
    signing_key: str = None
    signature_algo: Optional[str] = None
    digest_algo: str = 'sha256'
    certs_to_embed: List[str] = field(default_factory=list)

    @classmethod
    def process_entries(cls, config_dict):
        try:
            config_dict.setdefault('signing_key', config_dict['signing_cert'])
        except KeyError:
            pass

    @property
    def url(self):
        return f"{self.base_url}/{self.label}"


@dataclass(frozen=True)
class CRLRepoServiceInfo(ServiceInfo):
    for_issuer: str
    signing_key: str
    simulated_update_schedule: timedelta
    signature_algo: Optional[str] = None
    digest_algo: str = 'sha256'

    @classmethod
    def process_entries(cls, config_dict):
        try:
            upd_sched = config_dict['simulated_update_schedule']
            config_dict['simulated_update_schedule'] = parse_duration(upd_sched)
        except KeyError:
            pass
        try:
            config_dict.setdefault('signing_key', config_dict['signing_cert'])
        except KeyError:
            pass

    @property
    def repo_url(self):
        return f"{self.base_url}/{self.label}"

    @property
    def latest_url(self):
        return f"{self.repo_url}/latest.crl"

    def archive_url(self, for_crl_number):
        return f"{self.repo_url}/archive-{for_crl_number}.crl"


@dataclass(frozen=True)
class CertRepoServiceInfo(ServiceInfo):
    for_issuer: str
    publish_issued_certs: bool = True

    @property
    def repo_url(self):
        return f"{self.base_url}/{self.label}"

    @property
    def issuer_cert_url(self):
        return f"{self.repo_url}/ca.cert.pem"

    def issued_cert_url(self, label: str):
        if not self.publish_issued_certs:
            raise ConfigurationError(
                f"Cert repo '{self.label}' does not make issued certs public"
            )
        return f"{self.repo_url}/issued/{label}.cert.pem"


class OCSPInterface(RevocationInfoInterface):

    def __init__(self, for_issuer: str, pki_arch: PKIArchitecture):
        self.for_issuer = for_issuer
        self.pki_arch = pki_arch

    def get_issuer_cert(self) -> x509.Certificate:
        return self.pki_arch.get_cert(self.for_issuer)

    def check_revocation_status(self, cid: ocsp.CertId, at_time: datetime):
        cert_label = self.pki_arch.find_cert_label(
            cid, issuer_label=self.for_issuer
        )
        return self.pki_arch.check_revocation_status(cert_label, at_time)


class ServiceRegistry:
    def __init__(self, pki_arch: PKIArchitecture, base_url, service_config):
        self.services_base_url = base_url
        self.pki_arch = pki_arch

        def _gen_svc_config(url_suffix, configs):
            for lbl, cfg in configs.items():
                cfg = dict(cfg)
                cfg.setdefault('base-url', f"{base_url}/{url_suffix}")
                cfg['label'] = lbl
                yield lbl, cfg

        check_config_keys(
            'services', ('ocsp', 'crl-repo', 'cert-repo', 'time-stamping'),
            service_config
        )

        self._ocsp = {
            label: OCSPResponderServiceInfo.from_config(cfg)
            for label, cfg
            in _gen_svc_config('ocsp', service_config.get('ocsp', {}))
        }
        self._crl_repo = {
            label: CRLRepoServiceInfo.from_config(cfg)
            for label, cfg
            in _gen_svc_config('crls', service_config.get('crl-repo', {}))
        }
        self._cert_repo = {
            label: CertRepoServiceInfo.from_config(cfg)
            for label, cfg
            in _gen_svc_config('certs', service_config.get('cert-repo', {}))
        }
        self._tsa = {
            label: TSAServiceInfo.from_config(cfg)
            for label, cfg
            in _gen_svc_config('tsa', service_config.get('time-stamping', {}))
        }

    def get_ocsp_info(self, label) -> OCSPResponderServiceInfo:
        try:
            return self._ocsp[label]
        except KeyError as e:
            raise ConfigurationError(
                f"There is no registered OCSP service labelled '{label}'."
            ) from e

    def list_ocsp_responders(self) -> List[OCSPResponderServiceInfo]:
        return list(self._ocsp.values())

    def summon_responder(self, label, at_time=None) -> SimpleOCSPResponder:
        info = self.get_ocsp_info(label)
        responder_key = self.pki_arch.key_set.get_private_key(info.signing_key)
        return SimpleOCSPResponder(
            responder_cert=self.pki_arch.get_cert(info.responder_cert),
            responder_key=responder_key,
            signature_algo=choose_signed_digest(
                info.digest_algo, responder_key.algorithm,
                signature_algo=info.signature_algo
            ),
            at_time=at_time,
            revinfo_interface=OCSPInterface(
                for_issuer=info.for_issuer, pki_arch=self.pki_arch
            )
        )

    def get_crl_repo_info(self, label) -> CRLRepoServiceInfo:
        try:
            return self._crl_repo[label]
        except KeyError as e:
            raise ConfigurationError(
                f"There is no registered CRL repository labelled '{label}'."
            ) from e

    def list_crl_repos(self) -> List[CRLRepoServiceInfo]:
        return list(self._crl_repo.values())

    def get_cert_repo_info(self, label) -> CertRepoServiceInfo:
        try:
            return self._cert_repo[label]
        except KeyError as e:
            raise ConfigurationError(
                f"There is no registered certificate repository "
                f"labelled '{label}'."
            ) from e

    def get_tsa_info(self, label) -> TSAServiceInfo:
        try:
            return self._tsa[label]
        except KeyError as e:
            raise ConfigurationError(
                f"There is no registered time stamping service "
                f"labelled '{label}'."
            ) from e

    def list_time_stamping_services(self) -> List[TSAServiceInfo]:
        return list(self._tsa.values())

    def summon_timestamper(self, label, at_time=None) -> TimeStamper:
        # TODO allow policy parameter to be customised
        info = self.get_tsa_info(label)
        tsa_key = self.pki_arch.key_set.get_private_key(info.signing_key)
        return TimeStamper(
            tsa_cert=self.pki_arch.get_cert(info.label),
            tsa_key=tsa_key,
            fixed_dt=at_time,
            signature_algo=choose_signed_digest(
                info.digest_algo, key_algo=tsa_key.algorithm,
                signature_algo=info.signature_algo
            ),
            certs_to_embed=[
                self.pki_arch.get_cert(lbl) for lbl in info.certs_to_embed
            ],
            md_algorithm=info.digest_algo
        )

    def get_crl(self, repo_label, at_time: Optional[datetime] = None,
                number: Optional[int] = None):
        # TODO support indirect CRLs, delta CRLs, etc.?

        crl_info = self.get_crl_repo_info(repo_label)
        iss_cert = self.pki_arch.get_cert(crl_info.for_issuer)
        signing_key = self.pki_arch.key_set.get_private_key(
            crl_info.signing_key
        )

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
                    "trying to create an invalid CRL on purpose, pass in a CRL "
                    "number manually."
                )
            number = elapsed // time_delta
        this_update = time_origin + number * time_delta
        next_update = this_update + time_delta

        builder = CRLBuilder(
            issuer_cert=iss_cert, issuer_key=signing_key,
            signature_algo=choose_signed_digest(
                crl_info.digest_algo, signing_key.algorithm,
                signature_algo=crl_info.signature_algo
            )
        )

        revoked = list(
            self.pki_arch.get_revoked_certs_at_time(
                issuer_label=crl_info.for_issuer, at_time=this_update
            )
        )
        return builder.build_crl(
            crl_number=number, this_update=this_update,
            next_update=next_update, revoked_certs=revoked
        )


class CertomancerConfig:
    DEFAULT_BASE_URL = 'http://ca.example.com'

    @classmethod
    def from_yaml(cls, yaml_str) -> 'CertomancerConfig':
        config_dict = yaml.safe_load(yaml_str)
        return CertomancerConfig(config_dict)

    @classmethod
    def from_file(cls, cfg_path, working_dir=None) -> 'CertomancerConfig':
        cwd = None
        if working_dir is not None:
            cwd = os.getcwd()
            os.chdir(working_dir)
        try:
            with open(cfg_path, 'r') as inf:
                config_dict = yaml.safe_load(inf)
            return CertomancerConfig(config_dict)
        finally:
            if cwd is not None:
                os.chdir(cwd)

    def __init__(self, config, lazy_load_keys=False):
        self.base_url = base_url = config.get('base-url', self.DEFAULT_BASE_URL)
        try:
            key_set_cfg = config['keysets']
        except KeyError as e:
            raise ConfigurationError(
                "'keysets' must be present in configuration"
            ) from e

        self.key_sets = key_sets = KeySets(
            key_set_cfg, lazy_load_keys=lazy_load_keys
        )
        try:
            arch_cfgs = config['pki-architectures']
        except KeyError as e:
            raise ConfigurationError(
                "'pki-architectures' must be present in configuration"
            ) from e
        self.pki_archs = {
            arch.arch_label: arch
            for arch in PKIArchitecture.build_architectures(
                key_sets, arch_cfgs, base_url
            )
        }

    def get_pki_arch(self, label) -> PKIArchitecture:
        return self.pki_archs[label]
