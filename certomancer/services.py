import abc
import hashlib
import os
import struct
from dateutil.parser import parse as parse_dt
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

from oscrypto import asymmetric
from asn1crypto import keys, x509, tsp, algos, cms, core, crl, ocsp
import tzlocal

from certomancer.config_utils import ConfigurableMixin


class CertomancerServiceError(Exception):
    pass


def get_nonce() -> int:
    """
    Generate a random 8-byte integer

    (For testing use only)
    """
    # we initialise it like this to guarantee a fixed width
    return struct.unpack('>q', b'\x01' + os.urandom(7))[0]


def simple_cms_attribute(attr_type, value):
    """
    Convenience method to quickly construct a CMS attribute object with
    one value.

    :param attr_type:
        The attribute type, as a string or OID.
    :param value:
        The value.
    :return:
        A :class:`.cms.CMSAttribute` object.
    """
    return cms.CMSAttribute({
        'type': cms.CMSAttributeType(attr_type),
        'values': (value,)
    })


class TimeStamper:

    def __init__(self, tsa_cert: x509.Certificate,
                 tsa_key: keys.PrivateKeyInfo,
                 signature_algo: algos.SignedDigestAlgorithm = None,
                 certs_to_embed=None, fixed_dt: datetime = None,
                 policy=tsp.ObjectIdentifier('1.3.6.1.4.1.4146.2.3'),
                 md_algorithm='sha256'):
        self.tsa_cert = tsa_cert
        self.tsa_key = tsa_key
        self.certs_to_embed = list(certs_to_embed or ())
        self.fixed_dt = fixed_dt
        self.policy = policy
        self.md_algorithm = md_algorithm
        self.signature_algo = signature_algo or choose_signed_digest(
            md_algorithm, tsa_key.algorithm
        )

    def request_tsa_response(self, req: tsp.TimeStampReq) -> tsp.TimeStampResp:
        # We pretend that certReq is always true in the request

        status = tsp.PKIStatusInfo({'status': tsp.PKIStatus('granted')})
        message_imprint: tsp.MessageImprint = req['message_imprint']
        md_algorithm = self.md_algorithm
        digest_algorithm_obj = algos.DigestAlgorithm({
            'algorithm': md_algorithm
        })
        dt = self.fixed_dt or datetime.now(tz=tzlocal.get_localzone())
        tst_info = {
            'version': 'v1',
            'policy': self.policy,
            'message_imprint': message_imprint,
            'serial_number': get_nonce(),
            'gen_time': dt,
            'tsa': x509.GeneralName(
                name='directory_name', value=self.tsa_cert.subject
            )
        }
        try:
            tst_info['nonce'] = req['nonce']
        except KeyError:
            pass

        tst_info = tsp.TSTInfo(tst_info)
        tst_info_data = tst_info.dump()
        message_digest = getattr(hashlib, md_algorithm)(tst_info_data).digest()
        signing_cert_id = tsp.ESSCertID({
            'cert_hash': hashlib.sha1(self.tsa_cert.dump()).digest()
        })
        signed_attrs = cms.CMSAttributes([
            simple_cms_attribute('content_type', 'tst_info'),
            simple_cms_attribute(
                'signing_time', cms.Time({'utc_time': core.UTCTime(dt)})
            ),
            simple_cms_attribute(
                'signing_certificate',
                tsp.SigningCertificate({'certs': [signing_cert_id]})
            ),
            simple_cms_attribute('message_digest', message_digest),
        ])
        signature = generic_sign(
            self.tsa_key, signed_attrs.dump(), self.signature_algo
        )
        sig_info = cms.SignerInfo({
            'version': 'v1',
            'sid': cms.SignerIdentifier({
                'issuer_and_serial_number': cms.IssuerAndSerialNumber({
                    'issuer': self.tsa_cert.issuer,
                    'serial_number': self.tsa_cert.serial_number,
                })
            }),
            'digest_algorithm': digest_algorithm_obj,
            'signature_algorithm': self.signature_algo,
            'signed_attrs': signed_attrs,
            'signature': signature
        })
        certs = set(self.certs_to_embed)
        certs.add(self.tsa_cert)
        signed_data = {
            # must use v3 to get access to the EncapsulatedContentInfo construct
            'version': 'v3',
            'digest_algorithms': cms.DigestAlgorithms((digest_algorithm_obj,)),
            'encap_content_info': cms.EncapsulatedContentInfo({
                'content_type': cms.ContentType('tst_info'),
                'content': cms.ParsableOctetString(tst_info_data)
            }),
            'certificates': certs,
            'signer_infos': [sig_info]
        }
        tst = cms.ContentInfo({
            'content_type': cms.ContentType('signed_data'),
            'content': cms.SignedData(signed_data)
        })
        return tsp.TimeStampResp({'status': status, 'time_stamp_token': tst})


class CRLBuilder:
    def __init__(self, issuer_name: x509.Name,
                 issuer_key: keys.PrivateKeyInfo,
                 signature_algo: algos.SignedDigestAlgorithm,
                 authority_key_identifier: core.OctetString):
        self.issuer_name = issuer_name
        self.issuer_key = issuer_key
        self.signature_algo = signature_algo
        self.authority_key_identifier = authority_key_identifier

    def build_crl(self, crl_number: int,
                  this_update: datetime, next_update: datetime,
                  revoked_certs, distpoint: x509.DistributionPoint = None) \
            -> crl.CertificateList:
        tbs_crl = self.format_tbs_crl(
            crl_number=crl_number, this_update=this_update,
            revoked_certs=revoked_certs,
            next_update=next_update, distpoint=distpoint
        )
        return self.sign_crl(tbs_crl)

    def sign_crl(self, tbs_crl: crl.TbsCertList) -> crl.CertificateList:
        signature = generic_sign(
            self.issuer_key, tbs_crl.dump(), self.signature_algo
        )

        return crl.CertificateList({
            'tbs_cert_list': tbs_crl,
            'signature_algorithm': self.signature_algo,
            'signature': signature
        })

    @staticmethod
    def format_revoked_cert(serial: int, reason: crl.CRLReason,
                            revocation_date: datetime,
                            invalidity_date=None, extensions=None) \
            -> crl.RevokedCertificate:

        extensions = list(extensions or ())
        extensions.append(
            crl.CRLEntryExtension(
                {'extn_id': 'crl_reason', 'extn_value': reason}
            )
        )
        if invalidity_date:
            extensions.append(
                crl.CRLEntryExtension({
                    'extn_id': 'invalidity_date',
                    'extn_value': core.GeneralizedTime(invalidity_date)
                })
            )
        return crl.RevokedCertificate({
            'user_certificate': serial,
            'revocation_date': x509.Time({'general_time': revocation_date}),
            'crl_entry_extensions': extensions
        })

    def format_tbs_crl(self, crl_number: int, this_update: datetime,
                       revoked_certs, next_update: datetime,
                       distpoint: x509.DistributionPoint = None) \
            -> crl.TbsCertList:
        extensions = [
            crl.TBSCertListExtension({
                'extn_id': 'crl_number', 'extn_value':
                    core.ParsableOctetString(core.Integer(crl_number).dump())
            }),
            crl.TBSCertListExtension({
                'extn_id': 'authority_key_identifier',
                'extn_value': x509.AuthorityKeyIdentifier({
                    'key_identifier': self.authority_key_identifier
                })
            }),
        ]
        if distpoint is not None:
            extn_value = crl.IssuingDistributionPoint(distpoint)
            extensions.append(
                crl.TBSCertListExtension({
                    'extn_id': 'issuing_distribution_point',
                    'critical': True,
                    'extn_value': core.ParsableOctetString(extn_value.dump())
                })
            )
        revoked = crl.RevokedCertificates(revoked_certs)
        return crl.TbsCertList({
            'version': 'v2',
            'signature': self.signature_algo,
            'issuer': self.issuer_name,
            'this_update': x509.Time({'general_time': this_update}),
            'next_update': x509.Time({'general_time': next_update}),
            'revoked_certificates': revoked,
            'crl_extensions': crl.TBSCertListExtensions(extensions)
        })


def url_distribution_point(url, extra_urls=()):
    def _wrap(x):
        return x509.GeneralName({'uniform_resource_identifier': x})
    return {
        'distribution_point': {
            'full_name': [
                _wrap(url), *(_wrap(x) for x in extra_urls)
            ]
        }
    }


def choose_signed_digest(digest_algo: str, key_algo: str,
                         signature_algo: Optional[str] = None):
    if signature_algo is None:
        if key_algo == 'rsa':
            signature_algo = digest_algo + '_rsa'
        elif key_algo == 'dsa':
            signature_algo = digest_algo + '_dsa'
        elif key_algo == 'ec':
            signature_algo = digest_algo + '_ecdsa'

    signature_algo_obj = algos.SignedDigestAlgorithm(
        {'algorithm': signature_algo}
    )
    if signature_algo == 'rsassa_pss':
        # replicate default oscrypto PSS settings
        salt_len = len(getattr(hashlib, digest_algo)().digest())
        signature_algo_obj['parameters'] = algos.RSASSAPSSParams({
            'hash_algorithm': algos.DigestAlgorithm({
                'algorithm': digest_algo
            }),
            'mask_gen_algorithm': algos.MaskGenAlgorithm({
                'algorithm': 'mgf1',
                'parameters': algos.DigestAlgorithm(
                    {'algorithm': digest_algo}
                )
            }),
            'salt_length': salt_len
        })

    return signature_algo_obj


def generic_sign(private_key: keys.PrivateKeyInfo, tbs_bytes: bytes,
                 signature_algo: algos.SignedDigestAlgorithm) -> bytes:

    pk_algo = private_key.algorithm
    if pk_algo == 'rsa':
        if signature_algo.signature_algo == 'rsassa_pss':
            sign_fun = asymmetric.rsa_pss_sign
        else:
            sign_fun = asymmetric.rsa_pkcs1v15_sign
    elif pk_algo == 'ec':
        sign_fun = asymmetric.ecdsa_sign
    elif pk_algo == 'dsa':
        sign_fun = asymmetric.dsa_sign
    else:
        raise NotImplementedError(
            f"The cryptosystem '{pk_algo}' is not supported."
        )

    return sign_fun(
        asymmetric.load_private_key(private_key),
        tbs_bytes, signature_algo.hash_algo
    )


def issuer_match(cid: ocsp.CertId, candidate: x509.Certificate):
    # FIXME this doesn't really scale
    hash_algo = cid['hash_algorithm']['algorithm'].native

    # TODO implement the general case
    if hash_algo not in ('sha1', 'sha256'):
        raise NotImplementedError
    iss_name_hash = cid['issuer_name_hash'].native
    iss_key_hash = cid['issuer_key_hash'].native
    name_digest = getattr(candidate.subject, hash_algo)
    if name_digest != iss_name_hash:
        return False
    key_digest = getattr(candidate.public_key, hash_algo)
    return key_digest == iss_key_hash


@dataclass(frozen=True)
class RevocationStatus(ConfigurableMixin):
    revoked_since: datetime
    reason: crl.CRLReason
    invalid_since: datetime = None

    @classmethod
    def process_entries(cls, config_dict):
        super().process_entries(config_dict)
        try:
            revoked_since = config_dict['revoked_since']
        except KeyError:
            return
        config_dict['revoked_since'] = parse_dt(revoked_since)

        invalid_since = config_dict.get('invalid_since', None)
        if invalid_since is not None:
            config_dict['invalid_since'] = parse_dt(invalid_since)

        reason_spec = config_dict.get('reason', 'key_compromise')
        config_dict['reason'] = crl.CRLReason(reason_spec)

    def to_asn1(self, serial_number: int) -> crl.RevokedCertificate:
        return CRLBuilder.format_revoked_cert(
            serial_number, reason=self.reason,
            revocation_date=self.revoked_since,
            invalidity_date=self.invalid_since
        )


class RevocationInfoInterface(abc.ABC):

    def get_issuer_cert(self) -> x509.Certificate:
        raise NotImplementedError

    def check_revocation_status(self, cid: ocsp.CertId, at_time: datetime) \
            -> Optional[RevocationStatus]:
        raise NotImplementedError


class SimpleOCSPResponder:

    def __init__(self, responder_cert: x509.Certificate,
                 responder_key: keys.PrivateKeyInfo,
                 signature_algo: algos.SignedDigestAlgorithm,
                 at_time: datetime,
                 revinfo_interface: RevocationInfoInterface,
                 validity: timedelta = timedelta(minutes=10)):
        self.responder_cert = responder_cert
        self.responder_key = responder_key
        self.signature_algo = signature_algo
        self.at_time = at_time
        self.validity = validity
        self.revinfo_interface = revinfo_interface

    @staticmethod
    def build_error_response(error_status):
        return ocsp.OCSPResponse({'response_status': error_status})

    def build_ocsp_response(self, req: ocsp.OCSPRequest) -> ocsp.OCSPResponse:
        nonce = req.nonce_value.native
        requests = req['tbs_request']['request_list']
        issuer_cert = self.revinfo_interface.get_issuer_cert()
        err = SimpleOCSPResponder.build_error_response

        if len(requests) == 0:
            return err('malformed_request')

        responses = []
        for req_item in requests:
            cid: ocsp.CertId = req_item['req_cert']

            if not issuer_match(cid, issuer_cert):
                return err('unauthorized')

            try:
                revo = self.revinfo_interface.check_revocation_status(
                    cid, self.at_time
                )
            except NotImplementedError:
                return err('internal_error')
            except CertomancerServiceError:
                return err('unauthorized')

            if revo is None:
                cert_status = ocsp.CertStatus(name='good')
            else:
                cert_status = ocsp.CertStatus(
                    name='revoked', value={
                        'revocation_time': revo.revoked_since,
                        'revocation_reason': revo.reason
                    }
                )
            responses.append(
                ocsp.SingleResponse({
                    'cert_id': cid,
                    'cert_status': cert_status,
                    'this_update': self.at_time,
                    'next_update': self.at_time + self.validity
                })
            )

        rdata = ocsp.ResponseData({
            'responder_id': ocsp.ResponderId(
                name='by_key', value=self.responder_cert.public_key.sha1
            ),
            'produced_at': self.at_time,
            'responses': responses,
        })
        # TODO make extensions configurable in general
        #  (also for single responses)
        if nonce is not None:
            rdata['response_extensions'] = [
                ocsp.ResponseDataExtension({
                    'extn_id': 'nonce', 'extn_value': nonce
                })
            ]

        signature = generic_sign(
            self.responder_key, rdata.dump(),
            signature_algo=self.signature_algo
        )
        basic_resp = ocsp.BasicOCSPResponse({
            'tbs_response_data': rdata,
            'signature_algorithm': self.signature_algo,
            'signature': signature,
            'certs': [self.responder_cert]
        })
        response_bytes = ocsp.ResponseBytes({
            'response_type': 'basic_ocsp_response',
            'response': core.ParsableOctetString(basic_resp.dump())
        })
        return ocsp.OCSPResponse({
            'response_status': 'successful',
            'response_bytes': response_bytes
        })
