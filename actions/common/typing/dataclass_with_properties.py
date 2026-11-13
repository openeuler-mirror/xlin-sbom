# SPDX-FileCopyrightText: 2022 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
import typing
from dataclasses import dataclass


def _type_name(expected: typing.Any) -> str:
    return getattr(expected, "__name__", str(expected))


def _matches_type(value: typing.Any, expected: typing.Any) -> bool:
    """轻量运行时类型校验，替代原先的 beartype 依赖。

    仅覆盖 SPDX 模型使用到的 typing 构造（Optional/Union/List/Dict/Set/
    Tuple/Callable/Type），无法判定的构造按宽松处理，避免误报。
    """

    if expected is typing.Any or expected is None:
        return True
    if expected is type(None):
        return value is None
    if isinstance(expected, typing.TypeVar):
        return True

    origin = typing.get_origin(expected)
    args = typing.get_args(expected)

    union_type = getattr(__import__("types"), "UnionType", None)
    if origin is typing.Union or (union_type is not None and origin is union_type):
        return any(_matches_type(value, arg) for arg in args)

    if origin in (list, set, frozenset):
        if not isinstance(value, origin):
            return False
        return not args or all(_matches_type(item, args[0]) for item in value)

    if origin is tuple:
        if not isinstance(value, tuple):
            return False
        if not args:
            return True
        if len(args) == 2 and args[1] is Ellipsis:
            return all(_matches_type(item, args[0]) for item in value)
        if len(args) != len(value):
            return False
        return all(_matches_type(item, arg) for item, arg in zip(value, args))

    if origin is dict:
        if not isinstance(value, dict):
            return False
        if len(args) != 2:
            return True
        return all(_matches_type(key, args[0]) and _matches_type(item, args[1])
                   for key, item in value.items())

    if origin is not None:
        if origin.__name__ == "Callable":
            return callable(value)
        return True

    try:
        return isinstance(value, expected)
    except TypeError:
        return True


def dataclass_with_properties(cls):
    """Decorator to generate a dataclass with properties out of the class' value:type list.
    Their getters and setters will validate the declared types to ensure type conformity."""
    data_cls = dataclass(cls)
    for field_name, field_type in data_cls.__annotations__.items():
        set_field = make_setter(field_name, field_type)
        get_field = make_getter(field_name, field_type)

        setattr(data_cls, field_name, property(get_field, set_field))

    return data_cls


def make_setter(field_name, field_type):
    """helper method to avoid late binding when generating functions in a for loop"""

    def set_field(self, value: field_type):
        if not _matches_type(value, field_type):
            raise TypeError(
                f"Argument 'value' of type {type(value).__name__} does not "
                f"satisfy {_type_name(field_type)}")
        setattr(self, f"_{field_name}", value)

    def set_field_with_error_conversion(self, value: field_type):
        try:
            set_field(self, value)
        except TypeError as err:
            error_message: str = f"SetterError {self.__class__.__name__}: {err}"

            # As setters are created dynamically, their argument name is always "value". We replace it by the
            # actual name so the error message is more helpful.
            raise TypeError(error_message.replace("value", field_name, 1) + f": {value}")

    return set_field_with_error_conversion


def make_getter(field_name, field_type):
    """helper method to avoid late binding when generating functions in a for loop"""

    def get_field(self) -> field_type:
        return getattr(self, f"_{field_name}")

    return get_field
