from abc import ABC, abstractmethod
import re
from typing import (
    ClassVar,
    Optional,
    Union,
    List,
    Sequence,
    Dict,
    Type,
    get_origin,
    get_args,
    get_type_hints,
)
from collections.abc import Sequence as SequenceABC
from base64 import b64encode
from threatcode.types import (
    Placeholder,
    ThreatcodeBool,
    ThreatcodeCasedString,
    ThreatcodeExists,
    ThreatcodeExpansion,
    ThreatcodeFieldReference,
    ThreatcodeRegularExpressionFlag,
    ThreatcodeType,
    ThreatcodeString,
    ThreatcodeNumber,
    SpecialChars,
    ThreatcodeRegularExpression,
    ThreatcodeCompareExpression,
    ThreatcodeCIDRExpression,
)
from threatcode.conditions import ConditionAND
from threatcode.exceptions import ThreatcodeRuleLocation, ThreatcodeTypeError, ThreatcodeValueError
import threatcode


### Base Classes ###
class ThreatcodeModifier(ABC):
    """Base class for all Threatcode modifiers"""

    detection_item: "threatcode.rule.ThreatcodeDetectionItem"
    applied_modifiers: List["ThreatcodeModifier"]

    def __init__(
        self,
        detection_item: "threatcode.rule.ThreatcodeDetectionItem",
        applied_modifiers: List["ThreatcodeModifier"],
        source: Optional[ThreatcodeRuleLocation] = None,
    ):
        self.detection_item = detection_item
        self.applied_modifiers = applied_modifiers
        self.source = source

    def type_check(self, val: Union[ThreatcodeType, Sequence[ThreatcodeType]], explicit_type=None) -> bool:
        th = (
            explicit_type or get_type_hints(self.modify)["val"]
        )  # get type annotation from val parameter of apply method or explicit_type parameter
        to = get_origin(th)  # get possible generic type of type hint
        if to is None:  # Plain type in annotation
            return isinstance(val, th)
        elif to is Union:  # type hint is Union of multiple types, check if val is one of them
            for t in get_args(th):
                if isinstance(val, t):
                    return True
            return False
        elif to is SequenceABC:  # type hint is sequence
            inner_type = get_args(th)[0]
            return all([self.type_check(item, explicit_type=inner_type) for item in val])

    @abstractmethod
    def modify(
        self, val: Union[ThreatcodeType, Sequence[ThreatcodeType]]
    ) -> Union[ThreatcodeType, List[ThreatcodeType]]:
        """This method should be overridden with the modifier implementation."""

    def apply(self, val: Union[ThreatcodeType, Sequence[ThreatcodeType]]) -> List[ThreatcodeType]:
        """
        Modifier entry point containing the default operations:
        * Type checking
        * Ensure returned value is a list
        * Handle values of ThreatcodeExpansion objects separately.
        """
        if isinstance(val, ThreatcodeExpansion):  # Handle each ThreatcodeExpansion item separately
            return [ThreatcodeExpansion([va for v in val.values for va in self.apply(v)])]
        else:
            if not self.type_check(val):
                raise ThreatcodeTypeError(
                    f"Modifier {self.__class__.__name__} incompatible to value type of '{ val }'",
                    source=self.source,
                )
            r = self.modify(val)
            if isinstance(r, List):
                return r
            else:
                return [r]


class ThreatcodeValueModifier(ThreatcodeModifier):
    """Base class for all modifiers that handle each value for the modifier scope separately"""

    @abstractmethod
    def modify(self, val: ThreatcodeType) -> Union[ThreatcodeType, List[ThreatcodeType]]:
        """This method should be overridden with the modifier implementation."""


class ThreatcodeListModifier(ThreatcodeModifier):
    """Base class for all modifiers that handle all values for the modifier scope as a whole."""

    @abstractmethod
    def modify(self, val: Sequence[ThreatcodeType]) -> Union[ThreatcodeType, List[ThreatcodeType]]:
        """This method should be overridden with the modifier implementation."""


### Modifier Implementations ###
class ThreatcodeContainsModifier(ThreatcodeValueModifier):
    """Puts wildcards around a string to match it somewhere inside another string instead of as a whole."""

    def modify(
        self, val: Union[ThreatcodeString, ThreatcodeRegularExpression]
    ) -> Union[ThreatcodeString, ThreatcodeRegularExpression]:
        if isinstance(val, ThreatcodeString):
            if not val.startswith(SpecialChars.WILDCARD_MULTI):
                val = SpecialChars.WILDCARD_MULTI + val
            if not val.endswith(SpecialChars.WILDCARD_MULTI):
                val += SpecialChars.WILDCARD_MULTI
        elif isinstance(val, ThreatcodeRegularExpression):
            if val.regexp[:2] != ".*" and val.regexp[0] != "^":
                val.regexp = ".*" + val.regexp
            if val.regexp[-2:] != ".*" and val.regexp[-1] != "$":
                val.regexp = val.regexp + ".*"
            val.compile()
        return val


class ThreatcodeStartswithModifier(ThreatcodeValueModifier):
    """Puts a wildcard at the end of a string to match arbitrary values after the given prefix."""

    def modify(
        self, val: Union[ThreatcodeString, ThreatcodeRegularExpression]
    ) -> Union[ThreatcodeString, ThreatcodeRegularExpression]:
        if isinstance(val, ThreatcodeString):
            if not val.endswith(SpecialChars.WILDCARD_MULTI):
                val += SpecialChars.WILDCARD_MULTI
        elif isinstance(val, ThreatcodeRegularExpression):
            if val.regexp[-2:] != ".*" and val.regexp[-1] != "$":
                val.regexp = val.regexp + ".*"
            val.compile()
        return val


class ThreatcodeEndswithModifier(ThreatcodeValueModifier):
    """Puts a wildcard before a string to match arbitrary values before it."""

    def modify(
        self, val: Union[ThreatcodeString, ThreatcodeRegularExpression]
    ) -> Union[ThreatcodeString, ThreatcodeRegularExpression]:
        if isinstance(val, ThreatcodeString):
            if not val.startswith(SpecialChars.WILDCARD_MULTI):
                val = SpecialChars.WILDCARD_MULTI + val
        elif isinstance(val, ThreatcodeRegularExpression):
            if val.regexp[:2] != ".*" and val.regexp[0] != "^":
                val.regexp = ".*" + val.regexp
            val.compile()
        return val


class ThreatcodeBase64Modifier(ThreatcodeValueModifier):
    """Encode string as Base64 value."""

    def modify(self, val: ThreatcodeString) -> ThreatcodeString:
        if val.contains_special():
            raise ThreatcodeValueError(
                "Base64 encoding of strings with wildcards is not allowed",
                source=self.source,
            )
        return ThreatcodeString(b64encode(bytes(val)).decode())


class ThreatcodeBase64OffsetModifier(ThreatcodeValueModifier):
    """
    Encode string as Base64 value with different offsets to match it at different locations in
    encoded form.
    """

    start_offsets = (0, 2, 3)
    end_offsets = (None, -3, -2)

    def modify(self, val: ThreatcodeString) -> ThreatcodeExpansion:
        if val.contains_special():
            raise ThreatcodeValueError(
                "Base64 encoding of strings with wildcards is not allowed",
                source=self.source,
            )
        return ThreatcodeExpansion(
            [
                ThreatcodeString(
                    b64encode(i * b" " + bytes(val))[
                        self.start_offsets[i] : self.end_offsets[(len(val) + i) % 3]
                    ].decode()
                )
                for i in range(3)
            ]
        )


class ThreatcodeWideModifier(ThreatcodeValueModifier):
    """Encode string as wide string (UTF-16LE)."""

    def modify(self, val: ThreatcodeString) -> ThreatcodeString:
        r = list()
        for item in val.s:
            if isinstance(
                item, str
            ):  # put 0x00 after each character by encoding it to utf-16le and decoding it as utf-8
                try:
                    r.append(item.encode("utf-16le").decode("utf-8"))
                except UnicodeDecodeError:  # this method only works for ascii characters
                    raise ThreatcodeValueError(
                        f"Wide modifier only allowed for ascii strings, input string '{str(val)}' isn't one",
                        source=self.source,
                    )
            else:  # just append special characters without further handling
                r.append(item)

        s = ThreatcodeString()
        s.s = tuple(r)
        return s


class ThreatcodeWindowsDashModifier(ThreatcodeValueModifier):
    """
    Expand parameter characters / and - that are often interchangeable in Windows into the other
    form if it appears between word boundaries. E.g. in -param-name the first dash will be expanded
    into /param-name while the second dash is left untouched.
    """

    def modify(self, val: ThreatcodeString) -> ThreatcodeExpansion:
        def callback(p: Placeholder):
            if p.name == "_windash":
                yield from ("-", "/")
            else:
                yield p

        return ThreatcodeExpansion(
            val.replace_with_placeholder(re.compile("\\B[-/]\\b"), "_windash").replace_placeholders(
                callback
            )
        )


class ThreatcodeRegularExpressionModifier(ThreatcodeValueModifier):
    """Treats string value as (case-sensitive) regular expression."""

    def modify(self, val: ThreatcodeString) -> ThreatcodeRegularExpression:
        if len(self.applied_modifiers) > 0:
            raise ThreatcodeValueError(
                "Regular expression modifier only applicable to unmodified values",
                source=self.source,
            )
        return ThreatcodeRegularExpression(val.original)


class ThreatcodeRegularExpressionFlagModifier(ThreatcodeValueModifier):
    """Generic base class for setting a regular expression flag including checks"""

    flag: ClassVar[ThreatcodeRegularExpressionFlag]

    def modify(self, val: ThreatcodeRegularExpression) -> ThreatcodeRegularExpression:
        val.add_flag(self.flag)
        return val


class ThreatcodeRegularExpressionIgnoreCaseFlagModifier(ThreatcodeRegularExpressionFlagModifier):
    """Match regular expression case-insensitive."""

    flag: ClassVar[ThreatcodeRegularExpressionFlag] = ThreatcodeRegularExpressionFlag.IGNORECASE


class ThreatcodeRegularExpressionMultilineFlagModifier(ThreatcodeRegularExpressionFlagModifier):
    """Match regular expression across multiple lines."""

    flag: ClassVar[ThreatcodeRegularExpressionFlag] = ThreatcodeRegularExpressionFlag.MULTILINE


class ThreatcodeRegularExpressionDotAllFlagModifier(ThreatcodeRegularExpressionFlagModifier):
    """Regular expression dot matches all characters."""

    flag: ClassVar[ThreatcodeRegularExpressionFlag] = ThreatcodeRegularExpressionFlag.DOTALL


class ThreatcodeCaseSensitiveModifier(ThreatcodeValueModifier):
    def modify(self, val: ThreatcodeString) -> ThreatcodeCasedString:
        return ThreatcodeCasedString.from_threatcode_string(val)


class ThreatcodeCIDRModifier(ThreatcodeValueModifier):
    """Treat value as IP (v4 or v6) CIDR network."""

    def modify(self, val: ThreatcodeString) -> ThreatcodeCIDRExpression:
        if len(self.applied_modifiers) > 0:
            raise ThreatcodeValueError(
                "CIDR expression modifier only applicable to unmodified values",
                source=self.source,
            )
        return ThreatcodeCIDRExpression(str(val), source=self.source)


class ThreatcodeAllModifier(ThreatcodeListModifier):
    """Match all values of a list instead of any pf them."""

    def modify(self, val: Sequence[ThreatcodeType]) -> List[ThreatcodeType]:
        self.detection_item.value_linking = ConditionAND
        return val


class ThreatcodeCompareModifier(ThreatcodeValueModifier):
    """Base class for numeric comparison operator modifiers."""

    op: ClassVar[ThreatcodeCompareExpression.CompareOperators]

    def modify(self, val: ThreatcodeNumber) -> ThreatcodeCompareExpression:
        return ThreatcodeCompareExpression(val, self.op, self.source)


class ThreatcodeLessThanModifier(ThreatcodeCompareModifier):
    """Numeric less than (<) matching."""

    op: ClassVar[
        ThreatcodeCompareExpression.CompareOperators
    ] = ThreatcodeCompareExpression.CompareOperators.LT


class ThreatcodeLessThanEqualModifier(ThreatcodeCompareModifier):
    """Numeric less than or equal (<=) matching."""

    op: ClassVar[
        ThreatcodeCompareExpression.CompareOperators
    ] = ThreatcodeCompareExpression.CompareOperators.LTE


class ThreatcodeGreaterThanModifier(ThreatcodeCompareModifier):
    """Numeric greater than (>) matching."""

    op: ClassVar[
        ThreatcodeCompareExpression.CompareOperators
    ] = ThreatcodeCompareExpression.CompareOperators.GT


class ThreatcodeGreaterThanEqualModifier(ThreatcodeCompareModifier):
    """Numeric greater than or equal (>=) matching."""

    op: ClassVar[
        ThreatcodeCompareExpression.CompareOperators
    ] = ThreatcodeCompareExpression.CompareOperators.GTE


class ThreatcodeFieldReferenceModifier(ThreatcodeValueModifier):
    """Modifiers a plain string into the field reference type."""

    def modify(self, val: ThreatcodeString) -> ThreatcodeFieldReference:
        if val.contains_special():
            raise ThreatcodeValueError("Field references must not contain wildcards", source=self.source)
        return ThreatcodeFieldReference(val.to_plain())


class ThreatcodeExistsModifier(ThreatcodeValueModifier):
    """Modifies to check if the field name provided as value exists in the matched event."""

    def modify(self, val: ThreatcodeBool) -> ThreatcodeExists:
        if self.detection_item.field is None:
            raise ThreatcodeValueError("Exists modifier must be applied to field", source=self.source)
        if len(self.applied_modifiers) > 0:
            raise ThreatcodeValueError(
                "Exists modifier only applicable to unmodified boolean values",
                source=self.source,
            )
        return ThreatcodeExists(val.boolean)


class ThreatcodeExpandModifier(ThreatcodeValueModifier):
    """
    Modifier for expansion of placeholders in values. It replaces placeholder strings (%something%)
    with stub objects that are later expanded to one or multiple strings or replaced with some SIEM
    specific list item or lookup by the processing pipeline.
    """

    def modify(self, val: ThreatcodeString) -> ThreatcodeString:
        return val.insert_placeholders()


# Mapping from modifier identifier strings to modifier classes
modifier_mapping: Dict[str, Type[ThreatcodeModifier]] = {
    "contains": ThreatcodeContainsModifier,
    "startswith": ThreatcodeStartswithModifier,
    "endswith": ThreatcodeEndswithModifier,
    "exists": ThreatcodeExistsModifier,
    "base64": ThreatcodeBase64Modifier,
    "base64offset": ThreatcodeBase64OffsetModifier,
    "wide": ThreatcodeWideModifier,
    "windash": ThreatcodeWindowsDashModifier,
    "re": ThreatcodeRegularExpressionModifier,
    "i": ThreatcodeRegularExpressionIgnoreCaseFlagModifier,
    "ignorecase": ThreatcodeRegularExpressionIgnoreCaseFlagModifier,
    "m": ThreatcodeRegularExpressionMultilineFlagModifier,
    "multiline": ThreatcodeRegularExpressionMultilineFlagModifier,
    "s": ThreatcodeRegularExpressionDotAllFlagModifier,
    "dotall": ThreatcodeRegularExpressionDotAllFlagModifier,
    "cased": ThreatcodeCaseSensitiveModifier,
    "cidr": ThreatcodeCIDRModifier,
    "all": ThreatcodeAllModifier,
    "lt": ThreatcodeLessThanModifier,
    "lte": ThreatcodeLessThanEqualModifier,
    "gt": ThreatcodeGreaterThanModifier,
    "gte": ThreatcodeGreaterThanEqualModifier,
    "fieldref": ThreatcodeFieldReferenceModifier,
    "expand": ThreatcodeExpandModifier,
}

# Mapping from modifier class to identifier
reverse_modifier_mapping: Dict[str, str] = {
    modifier_class.__name__: identifier for identifier, modifier_class in modifier_mapping.items()
}
