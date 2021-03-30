import abc
import hashlib
import os
import os.path
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Iterable, Tuple
from zipfile import ZipFile

import yaml
from dateutil.parser import parse as parse_dt
from asn1crypto import x509, core, pem, ocsp
from dateutil.tz import tzlocal
from oscrypto import keys as oskeys, asymmetric
from asn1crypto.keys import PrivateKeyInfo, PublicKeyInfo

from .config_utils import (
    ConfigurationError, check_config_keys, LabelString,
    ConfigurableMixin, parse_duration, key_dashes_to_underscores, get_and_apply,
    pyca_cryptography_present
)
from .services import CertomancerServiceError, generic_sign, CRLBuilder, \
    choose_signed_digest, SimpleOCSPResponder, TimeStamper, \
    RevocationInfoInterface, RevocationStatus, url_distribution_point


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


class ProcessorLabel(LabelString):
    """
    Label referring to an extension processor (and the corresponding schema).
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
    """A labelled collection of keys."""

    def __init__(self, config, lazy_load_keys=False, working_dir=None):
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
        if working_dir is not None and not os.path.isabs(path_prefix):
            path_prefix = os.path.join(working_dir, path_prefix)

        # apply path prefix to key configs
        def _prepend(key_conf):
            try:
                key_conf['path'] = path_prefix + key_conf['path']
            except KeyError:
                pass
            return key_conf

        self._dict = {
            KeyLabel(k): KeyFromFile.from_config(
                KeyLabel(k), _prepend(v), lazy=lazy_load_keys
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

    def __init__(self, config, lazy_load_keys=False, working_dir=None):
        self._dict = {
            k: KeySet(v, lazy_load_keys=lazy_load_keys, working_dir=working_dir)
            for k, v in config.items()
        }

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


class SmartValueProcessor(abc.ABC):
    """Interface that supplies values for (certificate) extensions."""

    def provision(self, arch: 'PKIArchitecture', params):
        raise NotImplementedError


@dataclass(frozen=True)
class SmartValueSpec(ConfigurableMixin):
    """Class holding configuration for a smart value processor."""

    schema: ProcessorLabel
    params: dict = field(default_factory=dict)


class SmartValueProcessorRegistry:
    """
    Registry of smart value processor implementations for a given PKI
    architecture.
    """

    def __init__(self, arch: 'PKIArchitecture'):
        self.arch = arch
        self._dict = {}

    def register(self, schema_label: ProcessorLabel,
                 processor: SmartValueProcessor):
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
    """Specifies the value of a (certificate) extension."""

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
    through a smart value processor. Must be omitted if :attr:`value` is
    present.
    """

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

    def to_asn1(self, proc_registry: SmartValueProcessorRegistry,
                extn_id_class=x509.ExtensionId) -> x509.Extension:
        value = self.value
        if value is None and self.smart_value is not None:
            value = proc_registry.process_value(self.smart_value)

        return x509.Extension({
            'extn_id': extn_id_class(self.id),
            'critical': self.critical,
            'extn_value': value
        })


EXCLUDED_FROM_TEMPLATE = frozenset({'subject', 'subject_key'})


@dataclass(frozen=True)
class CertificateSpec(ConfigurableMixin):
    """Certificate specification."""

    label: CertLabel
    """Internal name of the certificate spec."""

    subject: EntityLabel
    """Certificate subject"""

    subject_key: KeyLabel
    """Subject's (public) key. Defaults to the value of :attr:`subject`."""

    issuer: EntityLabel
    """Certificate issuer"""

    authority_key: KeyLabel
    """Key of the authority issuing the certificate.
    Private key must be available. Defaults to the value of :attr:`issuer`."""

    validity: Validity
    """Validity period of the certificate."""

    _templatable_config: dict
    """Configuration that can be reused by other certificate specs."""

    signature_algo: Optional[str] = None
    """Signature algorithm designation. Certomancer will try to figure out
    something sensible if none is given."""

    issuer_cert: Optional[CertLabel] = None
    """
    Label of the issuer certificate to use. If the issuer only has one
    certificate, it is not necessary to provide a value for this field.
    
    The certificate is only used to make sure the authority key identifier
    in the generated certificate matches up with the issuer's subject key
    identifier. Certomancer calculates these by hashing the public key (as
    recommended by :rfc:`5280`, but in principle CAs can do whatever they want.
    """

    digest_algo: str = 'sha256'
    """Digest algorithm to use in the signing process. Defaults to SHA-256."""

    revocation: Optional[RevocationStatus] = None
    """Revocation status of the certificate, if relevant."""

    extensions: List[ExtensionSpec] = field(default_factory=list)
    """Extension settings for the certificate."""

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

    def resolve_issuer_cert(self, arch: 'PKIArchitecture') -> CertLabel:
        return self.issuer_cert or arch.get_unique_cert_for_entity(self.issuer)


DEFAULT_FIRST_SERIAL = 0x1000


class PKIArchitecture:
    """
    A collection of entities, keys, certificates and trust services, as
    modelled by Certomancer.
    """

    CONFIG_KEYS = (
        'keyset', 'entities', 'certs', 'services', 'entity-defaults'
    )

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
    def build_architectures(cls, key_sets: KeySets, cfgs, external_url_prefix,
                            smart_value_procs=None):
        if smart_value_procs is None:
            smart_value_procs = cls.default_smart_value_procs()
        for arch_label, cfg in cfgs.items():
            arch_label = ArchLabel(arch_label)
            check_config_keys(arch_label, PKIArchitecture.CONFIG_KEYS, cfg)
            service_base_url = cfg.get(
                'base-url', f"/{arch_label}"
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
            entities = EntityRegistry(
                entity_cfg, cfg.get('entity-defaults', None)
            )
            services = cfg.get('services', {})
            yield PKIArchitecture(
                arch_label, key_set=key_set, entities=entities,
                cert_spec_config=cert_specs,
                service_config=services,
                external_url_prefix=external_url_prefix,
                service_base_url=service_base_url,
                smart_value_procs=smart_value_procs
            )

    def __init__(self, arch_label: ArchLabel,
                 key_set: KeySet, entities: EntityRegistry,
                 cert_spec_config, service_config,
                 external_url_prefix, service_base_url,
                 smart_value_procs=None):

        if not service_base_url.startswith('/'):
            raise ConfigurationError(
                "Service base URL should start with '/'."
            )
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

        self.service_registry: ServiceRegistry = ServiceRegistry(
            self, external_url_prefix, service_base_url, service_config
        )

        # Parse certificate specs
        # This only processes the configuration, the actual signing etc.
        # happens on-demand
        cert_specs: Dict[CertLabel, CertificateSpec] = {}
        self._cert_specs = cert_specs
        self._cert_labels_by_issuer: Dict[EntityLabel, List[CertLabel]] \
            = defaultdict(list)
        self._cert_labels_by_subject: Dict[EntityLabel, List[CertLabel]] \
            = defaultdict(list)
        for name, cert_config in cert_spec_config.items():
            name = CertLabel(name)
            cert_config = key_dashes_to_underscores(cert_config)
            template = cert_config.pop('template', None)
            if template is not None:
                try:
                    template_spec: CertificateSpec = \
                        cert_specs[CertLabel(template)]
                except KeyError as e:
                    raise ConfigurationError(
                        f"Cert spec '{name}' refers to '{template}' as a "
                        f"template, but '{template}' hasn't been declared yet."
                    ) from e
                effective_cert_config = dict(template_spec._templatable_config)
                effective_cert_config.update(cert_config)
            else:
                effective_cert_config = dict(cert_config)

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

            cert_specs[name] = spec = CertificateSpec.from_config(
                effective_cert_config
            )
            self._cert_labels_by_issuer[spec.issuer].append(name)
            self._cert_labels_by_subject[spec.subject].append(name)

        self._cert_cache = {}

    def get_cert_spec(self, label: CertLabel) -> CertificateSpec:
        try:
            return self._cert_specs[label]
        except KeyError as e:
            raise CertomancerObjectNotFoundError(
                f"There is no registered certificate labelled '{label}'."
            ) from e

    def find_cert_label(self, cid: ocsp.CertId,
                        issuer_label: Optional[EntityLabel] = None) \
            -> CertLabel:
        # FIXME this doesn't really scale
        serial = cid['serial_number'].native
        if issuer_label is None:
            entities = self.entities
            name_hash = cid['issuer_name_hash'].native
            hash_algo = cid['hash_algorithm']['algorithm'].native
            try:
                issuer_label = next(
                    lbl for lbl in self._cert_labels_by_issuer.keys()
                    if entities.get_name_hash(lbl, hash_algo) == name_hash
                )
            except StopIteration as e:
                raise CertomancerServiceError(
                    f"Could not find a suitable issuer for CertID {cid.native}."
                ) from e

        specs = self._cert_labels_by_issuer[issuer_label]
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

    def enumerate_certs_by_issuer(self) \
            -> Iterable[Tuple[EntityLabel, Iterable[CertificateSpec]]]:
        for iss_label, issd_certs in self._cert_labels_by_issuer.items():
            yield iss_label, map(self.get_cert_spec, issd_certs)

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

        if password is None:
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

    def _dump_certs(self, use_pem=True, flat=False, include_pkcs12=False):
        include_pkcs12 &= pyca_cryptography_present()
        self._load_all_certs()
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
                    yield base_name + '.pfx', self.package_pkcs12(cert_label)

    def dump_certs(self, folder_path: str, use_pem=True, flat=False,
                   include_pkcs12=False):
        self._load_all_certs()
        os.makedirs(folder_path, exist_ok=True)
        itr = self._dump_certs(
            use_pem=use_pem, flat=flat, include_pkcs12=include_pkcs12
        )
        for name, data in itr:
            path = os.path.join(folder_path, name)
            if data is None:  # folder
                os.makedirs(path, exist_ok=True)
            else:
                with open(path, 'wb') as f:
                    f.write(data)

    def zip_certs(self, output_buffer, use_pem=True, flat=False,
                  include_pkcs12=False):
        zip_file = ZipFile(output_buffer, 'w')
        lbl = self.arch_label.value
        itr = self._dump_certs(
            use_pem=use_pem, flat=flat, include_pkcs12=include_pkcs12
        )
        for name, data in itr:
            if data is None:
                continue
            fname = os.path.join(lbl, name)
            zip_file.writestr(fname, data)
        zip_file.close()

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
            'extn_value': core.OctetString(ski)
        })
        if spec.self_signed:
            aki = ski
        else:
            issuer_cert_lbl = spec.resolve_issuer_cert(self)
            issuer_cert = self.get_cert(issuer_cert_lbl)
            aki = issuer_cert.key_identifier_value
        aki_value = x509.AuthorityKeyIdentifier({'key_identifier': aki})
        aki_extension = x509.Extension({
            'extn_id': 'authority_key_identifier',
            'critical': False,
            'extn_value': aki_value
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

    def get_revoked_certs_at_time(self, issuer_label: EntityLabel,
                                  at_time: datetime):
        labels = self._cert_labels_by_issuer[issuer_label]
        for cert_label in labels:
            revo = self.check_revocation_status(cert_label, at_time=at_time)
            cert = self.get_cert(cert_label)
            if revo is not None:
                yield revo.to_asn1(cert.serial_number)


@dataclass(frozen=True)
class ServiceInfo(ConfigurableMixin):
    label: ServiceLabel
    external_url_prefix: str
    base_url: str

    @property
    def internal_url(self):
        return f"{self.base_url}/{self.label}"

    @property
    def url(self):
        return f"{self.external_url_prefix}{self.base_url}/{self.label}"


@dataclass(frozen=True)
class OCSPResponderServiceInfo(ServiceInfo):
    for_issuer: EntityLabel
    responder_cert: CertLabel
    signing_key: Optional[KeyLabel] = None
    signature_algo: Optional[str] = None
    issuer_cert: Optional[CertLabel] = None
    digest_algo: str = 'sha256'

    @classmethod
    def process_entries(cls, config_dict):
        try:
            config_dict.setdefault('signing_key', config_dict['responder_cert'])
        except KeyError:
            pass

    def resolve_issuer_cert(self, arch: 'PKIArchitecture') -> CertLabel:
        return self.issuer_cert or \
               arch.get_unique_cert_for_entity(self.for_issuer)


@dataclass(frozen=True)
class TSAServiceInfo(ServiceInfo):
    signing_cert: CertLabel
    signing_key: Optional[KeyLabel] = None
    signature_algo: Optional[str] = None
    digest_algo: str = 'sha256'
    certs_to_embed: List[CertLabel] = field(default_factory=list)

    @classmethod
    def process_entries(cls, config_dict):
        try:
            config_dict.setdefault('signing_key', config_dict['signing_cert'])
        except KeyError:
            pass


@dataclass(frozen=True)
class CRLRepoServiceInfo(ServiceInfo):
    for_issuer: EntityLabel
    signing_key: KeyLabel
    simulated_update_schedule: timedelta
    issuer_cert: Optional[CertLabel] = None
    extra_urls: List[str] = field(default_factory=list)
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
    def latest_url(self):
        return f"{self.internal_url}/latest.crl"

    @property
    def latest_external_url(self):
        return f"{self.url}/latest.crl"

    def archive_url(self, for_crl_number):
        return f"{self.internal_url}/archive-{for_crl_number}.crl"

    def format_distpoint(self):
        return url_distribution_point(
            self.latest_external_url, self.extra_urls
        )

    def resolve_issuer_cert(self, arch: 'PKIArchitecture') -> CertLabel:
        return self.issuer_cert or \
               arch.get_unique_cert_for_entity(self.for_issuer)


@dataclass(frozen=True)
class CertRepoServiceInfo(ServiceInfo):
    for_issuer: EntityLabel
    issuer_cert: Optional[CertLabel] = None
    publish_issued_certs: bool = True

    @property
    def issuer_cert_url(self):
        return f"{self.internal_url}/ca.cert.pem"

    def issued_cert_url(self, label: CertLabel, use_pem=True):
        if not self.publish_issued_certs:
            raise ConfigurationError(
                f"Cert repo '{self.label}' does not make issued certs public"
            )
        fname = f"{label}.{'cert.pem' if use_pem else 'crt'}"
        return f"{self.internal_url}/issued/{fname}"


class OCSPInterface(RevocationInfoInterface):

    def __init__(self, for_issuer: EntityLabel, pki_arch: PKIArchitecture,
                 issuer_cert_label: CertLabel):
        self.for_issuer = for_issuer
        self.pki_arch = pki_arch
        self.issuer_cert_label = issuer_cert_label

    def get_issuer_cert(self) -> x509.Certificate:
        return self.pki_arch.get_cert(self.issuer_cert_label)

    def check_revocation_status(self, cid: ocsp.CertId, at_time: datetime):
        cert_label = self.pki_arch.find_cert_label(
            cid, issuer_label=self.for_issuer
        )
        return self.pki_arch.check_revocation_status(cert_label, at_time)


class ServiceRegistry:
    def __init__(self, pki_arch: PKIArchitecture, external_url_prefix,
                 base_url, service_config):
        self.services_base_url = base_url
        self.pki_arch = pki_arch

        def _gen_svc_config(url_suffix, configs):
            for lbl, cfg in configs.items():
                cfg = dict(cfg)
                cfg.setdefault('external-url-prefix', external_url_prefix)
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
        return SimpleOCSPResponder(
            responder_cert=self.pki_arch.get_cert(info.responder_cert),
            responder_key=responder_key,
            signature_algo=choose_signed_digest(
                info.digest_algo, responder_key.algorithm,
                signature_algo=info.signature_algo
            ),
            at_time=at_time,
            revinfo_interface=OCSPInterface(
                for_issuer=info.for_issuer, pki_arch=self.pki_arch,
                issuer_cert_label=issuer_cert_label
            )
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

    def list_cert_repos(self) -> List[CertRepoServiceInfo]:
        return list(self._cert_repo.values())

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
        return TimeStamper(
            tsa_cert=self.pki_arch.get_cert(info.signing_cert),
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

    def get_crl(self, repo_label: ServiceLabel,
                at_time: Optional[datetime] = None,
                number: Optional[int] = None):
        # TODO support indirect CRLs, delta CRLs, etc.?

        crl_info = self.get_crl_repo_info(repo_label)
        issuer_cert_label = crl_info.issuer_cert
        signing_key = self.pki_arch.key_set.\
            get_private_key(crl_info.signing_key)

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
                    "trying to create an invalid CRL on purpose, pass in a CRL "
                    "number manually."
                )
            number = elapsed // time_delta
        this_update = time_origin + number * time_delta
        next_update = this_update + time_delta

        builder = CRLBuilder(
            issuer_name=self.pki_arch.entities[crl_info.for_issuer],
            issuer_key=signing_key,
            signature_algo=choose_signed_digest(
                crl_info.digest_algo, signing_key.algorithm,
                signature_algo=crl_info.signature_algo
            ),
            authority_key_identifier=iss_cert.key_identifier_value
        )

        revoked = list(
            self.pki_arch.get_revoked_certs_at_time(
                issuer_label=crl_info.for_issuer, at_time=this_update
            )
        )
        return builder.build_crl(
            crl_number=number, this_update=this_update,
            next_update=next_update, revoked_certs=revoked,
            distpoint=crl_info.format_distpoint()
        )

    def get_cert_from_repo(self, repo_label: ServiceLabel,
                           cert_label: Optional[CertLabel] = None) \
            -> Optional[x509.Certificate]:

        repo_info = self.get_cert_repo_info(repo_label)
        arch = self.pki_arch
        if cert_label is None:
            # return the issuer's certificate
            cert_label = repo_info.issuer_cert
            if cert_label is None:
                issuer = repo_info.for_issuer
                # TODO: Should we return None if the issuer cert can't be
                #  determined, or let the error propagate?
                #  Choosing the latter for now.
                cert_label = arch.get_unique_cert_for_entity(issuer)
        else:
            # check if the cert in question actually belongs to the repo
            # (i.e. whether it is issued by the right entity)
            cert_spec = arch.get_cert_spec(cert_label)
            if cert_spec.issuer != repo_info.for_issuer:
                return None
        return arch.get_cert(cert_label)


class CertomancerConfig:
    DEFAULT_EXTERNAL_URL_PREFIX = 'http://ca.example.com'

    @classmethod
    def from_yaml(cls, yaml_str, working_dir=None) -> 'CertomancerConfig':
        config_dict = yaml.safe_load(yaml_str)
        return CertomancerConfig(config_dict, working_dir=working_dir)

    @classmethod
    def from_file(cls, cfg_path, working_dir=None) -> 'CertomancerConfig':
        with open(cfg_path, 'r') as inf:
            config_dict = yaml.safe_load(inf)
        return CertomancerConfig(config_dict, working_dir=working_dir)

    def __init__(self, config, lazy_load_keys=False, working_dir=None):
        self.external_url_prefix = external_url_prefix = config.get(
            'external-url-prefix', self.DEFAULT_EXTERNAL_URL_PREFIX
        )
        try:
            key_set_cfg = config['keysets']
        except KeyError as e:
            raise ConfigurationError(
                "'keysets' must be present in configuration"
            ) from e

        self.key_sets = key_sets = KeySets(
            key_set_cfg, lazy_load_keys=lazy_load_keys,
            working_dir=working_dir
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
                key_sets, arch_cfgs, external_url_prefix=external_url_prefix
            )
        }

    def get_pki_arch(self, label: ArchLabel) -> PKIArchitecture:
        return self.pki_archs[label]
