from typing import Any, Dict, List, Optional, Set, Tuple

import pkcs11
from asn1crypto import core, keys, x509
from pkcs11.util import biginteger, dsa, rsa
from pkcs11.util import x509 as p11_x509

from certomancer import PKIArchitecture
from certomancer.registry import CertLabel

__all__ = [
    'Alchemist',
    'AlchemistBackend',
    'DefaultAlchemistBackend',
    'open_pkcs11_session',
]


class AlchemistBackend:
    """
    Alchemist backend to interface with a hardware token.
    """

    def private_key_to_token(
        self,
        key: keys.PrivateKeyInfo,
        label: str,
        id_attr: bytes,
        attrs: Optional[Dict[pkcs11.Attribute, Any]] = None,
    ):
        """
        Save a private key on the token.

        :param key:
           Private key to save.
        :param label:
            PKCS#11 label to set.
        :param id_attr:
            PKCS#11 ID attribute to set.
        :param attrs:
            Additional PKCS#11 attributes.
        """
        raise NotImplementedError

    def cert_to_token(
        self,
        cert: x509.Certificate,
        label: str,
        id_attr: bytes,
        attrs: Optional[Dict[pkcs11.Attribute, Any]] = None,
    ):
        """
        Save a certificate on the token.

        :param cert:
           Certificate to save.
        :param label:
            PKCS#11 label to set.
        :param id_attr:
            PKCS#11 ID attribute to set.
        :param attrs:
            Additional PKCS#11 attributes.
        """
        raise NotImplementedError


def open_pkcs11_session(
    lib_location: str,
    slot_no: Optional[int] = None,
    token_label: Optional[str] = None,
    pin: Optional[str] = None,
    as_so: bool = False,
    rw: bool = True,
) -> pkcs11.Session:
    """
    Open a PKCS#11 session

    :param lib_location:
        Path to the PKCS#11 module.
    :param slot_no:
        Slot number to use. If not specified, the first slot containing a token
        labelled ``token_label`` will be used.
    :param token_label:
        Label of the token to use. If ``None``, there is no constraint.
    :param pin:
        User PIN to use.
    :param as_so:
        Pass PIN as SO pin instead of user pin.
    :param rw:
        Open the token in read-write mode (defaults to ``True``).
    :return:
        An open PKCS#11 session object.
    """
    lib = pkcs11.lib(lib_location)

    slots = lib.get_slots()
    token = None
    if slot_no is None:
        for slot in slots:
            try:
                token = slot.get_token()
                if token_label is None or token.label == token_label:
                    break
            except pkcs11.PKCS11Error:
                continue
        if token is None:
            raise pkcs11.PKCS11Error(
                f'No token with label {token_label} found'
                if token_label is not None
                else 'No token found'
            )
    else:
        token = slots[slot_no].get_token()
        if token_label is not None and token.label != token_label:
            raise pkcs11.PKCS11Error(
                f'Token in slot {slot_no} is not {token_label}.'
            )

    kwargs: Dict[str, Any]
    kwargs = {'rw': rw}
    if pin is not None:
        kwargs['so_pin' if as_so else 'user_pin'] = pin

    return token.open(**kwargs)


class DefaultAlchemistBackend(AlchemistBackend):
    def __init__(self, session: pkcs11.Session):
        self._session = session

    def private_key_to_token(
        self,
        key: keys.PrivateKeyInfo,
        label: str,
        id_attr: bytes,
        attrs: Optional[Dict[pkcs11.Attribute, Any]] = None,
    ):
        algo = key.algorithm
        obj_attrs = {}
        if algo == 'rsa':
            key_bytes = bytes(key['private_key'])
            obj_attrs.update(
                rsa.decode_rsa_private_key(key_bytes, pkcs11.MechanismFlag(0))
            )
        elif algo == 'ec':
            ec_key: keys.ECPrivateKey = key['private_key'].parsed
            params = ec_key['parameters']
            if params is core.VOID:
                params = key['private_key_algorithm']['parameters']
            obj_attrs.update(
                {
                    pkcs11.Attribute.KEY_TYPE: pkcs11.KeyType.EC,
                    pkcs11.Attribute.EC_PARAMS: params.dump(),
                    pkcs11.Attribute.VALUE: ec_key['private_key'].contents,
                }
            )
        elif algo == 'dsa':
            obj_attrs = dsa.decode_dsa_domain_parameters(
                key['private_key_algorithm']['parameters'].dump()
            )
            obj_attrs[pkcs11.Attribute.VALUE] = biginteger(
                key['private_key'].parsed.native
            )
            obj_attrs[pkcs11.Attribute.KEY_TYPE] = pkcs11.KeyType.DSA
        elif algo in ('ed25519', 'ed448'):
            # we encode the params using the RFC 8032 curve name convention
            # See 2.3.6 in the PCKS #11 3.0 current mechanisms specification
            params = core.PrintableString(
                'edwards25519' if algo == 'ed25519' else 'edwards448'
            )
            obj_attrs.update(
                {
                    pkcs11.Attribute.KEY_TYPE: pkcs11.KeyType.EC_EDWARDS,
                    pkcs11.Attribute.EC_PARAMS: params.dump(),
                    pkcs11.Attribute.VALUE: key['private_key'].parsed.native,
                }
            )
        else:
            raise NotImplementedError(f"Algorithm {algo!r} is not supported")

        obj_attrs[pkcs11.Attribute.SIGN] = True
        obj_attrs[pkcs11.Attribute.TOKEN] = True
        obj_attrs[pkcs11.Attribute.LABEL] = label
        obj_attrs[pkcs11.Attribute.CLASS] = pkcs11.ObjectClass.PRIVATE_KEY
        obj_attrs[pkcs11.Attribute.ID] = id_attr
        obj_attrs[pkcs11.Attribute.EXTRACTABLE] = False
        obj_attrs[pkcs11.Attribute.SENSITIVE] = True
        if attrs:
            obj_attrs.update(attrs)
        self._session.create_object(obj_attrs)

    def cert_to_token(
        self,
        cert: x509.Certificate,
        label: str,
        id_attr: bytes,
        attrs: Optional[Dict[pkcs11.Attribute, Any]] = None,
    ):
        obj_attrs = p11_x509.decode_x509_certificate(cert.dump())
        obj_attrs[pkcs11.Attribute.TOKEN] = True
        obj_attrs[pkcs11.Attribute.LABEL] = label
        obj_attrs[pkcs11.Attribute.ID] = id_attr
        if attrs:
            obj_attrs.update(attrs)
        self._session.create_object(obj_attrs)


class Alchemist:
    """
    The Alchemist is a tool to move Certomancer's PKI architectures onto
    PKCS#11 tokens.

    :param backend:
        The backend implementation to use.
    :param pki_arch:
        The PKI architecture to interact with.
    """

    def __init__(self, backend: AlchemistBackend, pki_arch: PKIArchitecture):
        self._backend = backend
        self.pki_arch = pki_arch

    def _get_key_bundle_for(
        self, lbl: CertLabel
    ) -> Tuple[str, x509.Certificate, keys.PrivateKeyInfo]:
        arch = self.pki_arch
        spec = arch.get_cert_spec(lbl)
        cert = arch.get_cert(lbl)
        key = self.pki_arch.key_set.get_private_key(spec.subject_key)
        return str(lbl), cert, key

    def store_key_bundles(
        self, certs: Set[CertLabel], include_chains: bool = True
    ):
        """
        Store key-certificate from a :class:`.PKIArchitecture` pairs on
        a PKCS#11 token.

        The PKCS#11 label and ID attributes for both the keys and
        the certificates will be assigned based on the certificate's label
        in the Certomancer config.

        Note that private keys with multiple associated certificates will not
        be deduplicated.

        :param certs:
            The set of certificate labels for which both the certificates
            and the corresponding private keys should be installed on the token.
        :param include_chains:
            If ``True`` (the default), also save certificates relevant to the
            ``certs``' chain of trust.

            .. note::
                The private keys for these certificates will not be saved.
        """

        extra_cert_lbls: Set[CertLabel]
        if include_chains:
            extra_cert_lbls = {
                iss_lbl
                for lbl in certs
                for iss_lbl in self.pki_arch.get_chain(lbl)
            }
        else:
            extra_cert_lbls = set()

        # make sure there's no overlap in writes
        extra_cert_lbls -= certs

        # make sure we have all the info we need before doing any writes,
        # so we get the errors out of the way before making any hard-to-reverse
        # changes on the actual token
        bundles: List[Tuple[str, x509.Certificate, keys.PrivateKeyInfo]] = [
            self._get_key_bundle_for(lbl) for lbl in certs
        ]
        extra_certs: List[Tuple[str, x509.Certificate]] = [
            (str(lbl), self.pki_arch.get_cert(lbl)) for lbl in extra_cert_lbls
        ]

        for cert_lbl, cert in extra_certs:
            self._backend.cert_to_token(
                cert=cert, label=cert_lbl, id_attr=cert_lbl.encode('utf8')
            )

        for bundle_lbl, cert, priv_key in bundles:
            bundle_id = bundle_lbl.encode('utf8')
            self._backend.cert_to_token(
                cert=cert, label=bundle_lbl, id_attr=bundle_id
            )
            # Note: this will duplicate private keys for which
            # more than one certificate has been issued.
            # We don't dedupe by default because some PKCS#11 client
            # implementations make assumptions about labels & ids
            # to pair up keys and certs, but it might be good to
            # support that use case as well (?)
            self._backend.private_key_to_token(
                key=priv_key, label=bundle_lbl, id_attr=bundle_id
            )
