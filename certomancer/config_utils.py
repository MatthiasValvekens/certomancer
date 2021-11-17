"""
This module contains utilities for allowing dataclasses to be populated by
user-provided configuration (e.g. from a Yaml file).

.. note::
    On naming conventions: this module converts hyphens in key names to
    underscores as a matter of course.
"""

import dataclasses
import re
import os.path
from collections.abc import Callable

from datetime import timedelta


__all__ = [
    'ConfigurationError', 'ConfigurableMixin', 'check_config_keys',
    'parse_duration', 'key_dashes_to_underscores', 'get_and_apply',
    'LabelString', 'SearchDir',
    'plugin_instantiate_util'
]

from typing import Optional

_noneType = type(None)


class LabelString:
    """
    Class that can be subclassed to get (somewhat) type-safe label strings.
    Configurable dataclasses deal with these automagically.

    This wrapper is only intended as a way to help with type hinting,
    its ``__eq__`` and ``__hash__`` operations delegate to the
    underlying string.
    """

    __slots__ = ['value']

    @staticmethod
    def get_subclass(thing) -> Optional[type]:
        """
        Figure out if the annotation 'thing' describes a label type.
        Used in config ingestion logic to instantiate dataclasses.

        :param thing:
            A type annotation.
        """

        if isinstance(thing, type):
            the_type = thing
        else:
            try:
                from typing import get_args
            except ImportError:
                def get_args(tp):
                    try:
                        return tp.__args__
                    except AttributeError:
                        return ()

            # is it an optional? (i.e. Union[X, None])
            # if so, retrieve the wrapped type
            try:
                type1, type2 = get_args(thing)
                if type2 is not _noneType:
                    return None
            except (ValueError, TypeError):
                return None
            the_type = type1
        return the_type if issubclass(the_type, LabelString) else None

    def __init__(self, value: str):
        if not isinstance(value, str):
            raise TypeError
        self.value = value

    def __str__(self):
        return self.value

    def __repr__(self):
        return f"{self.__class__.__name__}('{self.value}')"

    def __hash__(self):
        return hash(self.value)

    def __eq__(self, other):
        return str(self) == str(other)


class ConfigurationError(ValueError):
    """Signal configuration errors."""
    pass


def key_dashes_to_underscores(config_dict):
    return {
        key.replace('-', '_'): v for key, v in config_dict.items()
    }


@dataclasses.dataclass(frozen=True)
class ConfigurableMixin:
    """General configuration mixin for dataclasses"""

    @classmethod
    def process_entries(cls, config_dict):
        """
        Hook method that can modify the configuration dictionary
        to overwrite or tweak some of their values (e.g. to convert string
        parameters into more complex Python objects)

        Subclasses that override this method should call
        ``super().process_entries()``, and leave keys that they do not
        recognise untouched.

        :param config_dict:
            A dictionary containing configuration values.
        :raises ConfigurationError:
            when there is a problem processing a relevant entry.
        """
        pass

    @classmethod
    def from_config(cls, config_dict):
        """
        Attempt to instantiate an object of the class on which it is called,
        by means of the configuration settings passed in.

        First, we check that the keys supplied in the dictionary correspond
        to data fields on the current class.
        Then, the dictionary is processed using the :meth:`process_entries`
        method. The resulting dictionary is passed to the initialiser
        of the current class as a kwargs dict.

        :param config_dict:
            A dictionary containing configuration values.
        :return:
            An instance of the class on which it is called.
        :raises ConfigurationError:
            when an unexpected configuration key is encountered or left
            unfilled, or when there is a problem processing one of the config
            values.
        """
        check_config_keys(
            cls.__name__, {f.name for f in dataclasses.fields(cls)},
            config_dict
        )
        # in Python we need underscores
        config_dict = key_dashes_to_underscores(config_dict)
        cls.process_entries(config_dict)

        # wrap strings in the appropriate label type where necessary
        def _label_fields():
            for f in dataclasses.fields(cls):
                maybe_label_type = LabelString.get_subclass(f.type)
                if maybe_label_type is not None:
                    yield f.name, maybe_label_type

        for fname, label_type in _label_fields():
            try:
                label_str = config_dict[fname]
                if label_str is None:
                    continue
                config_dict[fname] = label_type(label_str)
            except KeyError:
                continue
        try:
            # noinspection PyArgumentList
            return cls(**config_dict)
        except TypeError as e:  # pragma: nocover
            raise ConfigurationError(e)


def check_config_keys(config_name, expected_keys, config_dict):
    # wrapper function to provide user-friendly errors
    #  (mainly intended for the CLI)
    # TODO What about type checking?
    if not isinstance(config_dict, dict):  # pragma: nocover
        raise ConfigurationError(
            f"{config_name} requires a dictionary to initialise."
        )
    # standardise on dashes for the yaml interface
    provided_keys = {key.replace('_', '-') for key in config_dict.keys()}
    expected_keys = {key.replace('_', '-') for key in expected_keys}
    if not (provided_keys <= expected_keys):
        unexpected_keys = provided_keys - expected_keys
        # this is easier to present to the user than a TypeError
        raise ConfigurationError(
            f"Unexpected {'key' if len(unexpected_keys) == 1 else 'keys'} "
            f"in configuration for {config_name}: "
            f"{','.join(key.replace('_', '-') for key in unexpected_keys)}."
        )


DURATION_REGEX_PARTS = re.compile(
    r"P(?P<days>[0-9YMWD]+)?(?:(?:(?<=P)T?|T)(?P<time>[0-9HMS]+))?"
)
DURATION_REGEX_DAYS = re.compile(
    r"(?:(?P<years>\d+)Y)?(?:(?P<months>\d+)M)?"
    r"(?:(?P<weeks>\d+)W)?(?:(?P<days>\d+)D)?"
)

DURATION_REGEX_TIME = re.compile(
    r"(?:(?P<hours>\d+)H)?(?:(?P<minutes>\d+)M)?(?:(?P<seconds>\d+)S)?"
)


def parse_duration(input_str) -> timedelta:
    m = DURATION_REGEX_PARTS.fullmatch(input_str)
    if m is None:
        raise ValueError(f"Failed to parse duration string {input_str}")
    days_part = m.group('days')
    time_part = m.group('time')

    if days_part is not None:
        days_m = DURATION_REGEX_DAYS.fullmatch(days_part)
        if days_m is None:
            raise ValueError(f"Failed to parse duration string {input_str}")
        # these designations can't be represented with timedelta objects
        unsupported = (days_m.group('years'), days_m.group('months'))
        if not all(x is None for x in unsupported):
            raise ValueError(
                "ISO 8601 year/month designations cannot be reliably "
                "represented using timedelta objects, so they aren't allowed."
            )

        weeks = int(days_m.group('weeks') or 0)
        days = int(days_m.group('days') or 0) + 7 * weeks
    else:
        days = 0

    if time_part is not None:
        time_m = DURATION_REGEX_TIME.fullmatch(time_part)
        if time_m is None:
            raise ValueError(f"Failed to parse duration string {input_str}")

        hours = int(time_m.group('hours') or 0)
        minutes = int(time_m.group('minutes') or 0)
        seconds = int(time_m.group('seconds') or 0)
    else:
        hours = minutes = seconds = 0

    return timedelta(days=days, hours=hours, minutes=minutes, seconds=seconds)


def get_and_apply(dictionary: dict, key, function: Callable, *, default=None):
    try:
        value = dictionary[key]
    except KeyError:
        return default
    return function(value)


class SearchDir:
    root_path: str

    def __init__(self, root_path: str):
        self.root_path = os.path.abspath(root_path)

    def resolve(self, path):
        joined = os.path.join(self.root_path, path)
        abs_path = os.path.abspath(joined)
        if os.path.commonpath([self.root_path, abs_path]) != self.root_path:
            raise ConfigurationError(
                f"Path '{joined}' does not resolve to a directory "
                f"under '{self.root_path}'."
            )
        return abs_path

    def search_subdir(self, path):
        return SearchDir(self.resolve(path))

    def __repr__(self):
        return f"SearchDir('{self.root_path}')"

    def __str__(self):
        return self.root_path


def plugin_instantiate_util(plugin):
    if isinstance(plugin, type):
        cls = plugin
        # try to instantiate the class
        try:
            plugin = cls()
        except TypeError as e:
            raise ConfigurationError(
                f"Failed to instantiate plugin of type {cls.__name__}"
            ) from e
    else:
        cls = plugin.__class__

    return plugin, cls


