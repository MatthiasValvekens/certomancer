import hashlib

from asn1crypto import x509

from ..config_utils import key_dashes_to_underscores
from .common import CertomancerObjectNotFoundError, EntityLabel


class EntityRegistry:
    """A registry of entities.

    Entities are internally identified by their labels, which can be converted
    to distinguished names via the ``__getitem__`` accessor on the entity
    registry to which they belong.
    """

    def __init__(self, config, defaults=None):
        defaults = (
            {} if defaults is None else key_dashes_to_underscores(defaults)
        )

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


def as_general_name(name: x509.Name) -> x509.GeneralName:
    # note for readability: the 'name' parameter below is part of the Choice
    # API in asn1crypto, and has nothing to do with the fact that we're dealing
    # with name objects here
    return x509.GeneralName(name='directory_name', value=name)
