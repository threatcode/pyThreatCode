from dataclasses import dataclass
from typing import ClassVar, List
from threatcode.modifiers import (
    ThreatcodeContainsModifier,
    ThreatcodeEndswithModifier,
    ThreatcodeStartswithModifier,
)
from threatcode.rule import ThreatcodeDetectionItem
from threatcode.types import ThreatcodeString, SpecialChars
from threatcode.validators.base import (
    ThreatcodeDetectionItemValidator,
    ThreatcodeStringValueValidator,
    ThreatcodeValidationIssue,
    ThreatcodeValidationIssueSeverity,
)


@dataclass
class DoubleWildcardIssue(ThreatcodeValidationIssue):
    description: ClassVar[str] = "String contains multiple consecutive * wildcards"
    severity: ClassVar[ThreatcodeValidationIssueSeverity] = ThreatcodeValidationIssueSeverity.LOW
    string: ThreatcodeString


class DoubleWildcardValidator(ThreatcodeStringValueValidator):
    """Check strings for consecutive multi-character wildcards."""

    def validate_value(self, value: ThreatcodeString) -> List[ThreatcodeValidationIssue]:
        prev_wildcard = False
        for c in value.s:
            if c == SpecialChars.WILDCARD_MULTI:
                if prev_wildcard:  # previous character was also a wildcard
                    return [DoubleWildcardIssue([self.rule], value)]
                else:
                    prev_wildcard = True
            else:
                prev_wildcard = False
        return []


@dataclass
class NumberAsStringIssue(ThreatcodeValidationIssue):
    description: ClassVar[str] = "A number was expressed as string"
    severity: ClassVar[ThreatcodeValidationIssueSeverity] = ThreatcodeValidationIssueSeverity.LOW
    string: ThreatcodeString


class NumberAsStringValidator(ThreatcodeStringValueValidator):
    """Check numbers that were expressed as strings."""

    def validate_value(self, value: ThreatcodeString) -> List[ThreatcodeValidationIssue]:
        if len(value.s) == 1 and isinstance(value.s[0], str) and not " " in value.s[0]:
            try:
                int(value.s[0])
                return [NumberAsStringIssue(self.rule, value)]
            except ValueError:
                pass
        return []


@dataclass
class ControlCharacterIssue(ThreatcodeValidationIssue):
    description: ClassVar[
        str
    ] = "String contains control character likely caused by missing (double-)slash"
    severity: ClassVar[ThreatcodeValidationIssueSeverity] = ThreatcodeValidationIssueSeverity.HIGH
    string: ThreatcodeString


class ControlCharacterValidator(ThreatcodeStringValueValidator):
    """
    Check for control characters in string values, which are normally inserted unintentionally by
    wrong usage of single backslashes, e.g. before a t character, where double backslashes are required.
    """

    def validate_value(self, value: ThreatcodeString) -> List[ThreatcodeValidationIssue]:
        if any((ord(c) < 31 for s in value.s for c in (s if isinstance(s, str) else ""))):
            return [ControlCharacterIssue([self.rule], value)]
        else:
            return []


@dataclass
class WildcardsInsteadOfContainsModifierIssue(ThreatcodeValidationIssue):
    description: ClassVar[
        str
    ] = "String contains wildcards at beginning and end instead of being modified with contains modifier"
    severity: ClassVar[ThreatcodeValidationIssueSeverity] = ThreatcodeValidationIssueSeverity.LOW
    detection_item: ThreatcodeDetectionItem


@dataclass
class WildcardInsteadOfStartswithIssue(ThreatcodeValidationIssue):
    description: ClassVar[
        str
    ] = "String contains wildcard at end instead of being modified with startswith modifier"
    severity: ClassVar[ThreatcodeValidationIssueSeverity] = ThreatcodeValidationIssueSeverity.LOW
    detection_item: ThreatcodeDetectionItem


@dataclass
class WildcardInsteadOfEndswithIssue(ThreatcodeValidationIssue):
    description: ClassVar[
        str
    ] = "String contains wildcard at beginning instead of being modified with endswith modifier"
    severity: ClassVar[ThreatcodeValidationIssueSeverity] = ThreatcodeValidationIssueSeverity.LOW
    detection_item: ThreatcodeDetectionItem


class WildcardsInsteadOfModifiersValidator(ThreatcodeDetectionItemValidator):
    """Check if wildcards were used where usage of startswith, endswith and contains modifiers would be possible."""

    def validate_detection_item(
        self, detection_item: ThreatcodeDetectionItem
    ) -> List[ThreatcodeValidationIssue]:
        # Warning rule use a single '*' waiting for the `exists` modifier  so check len(value)>1 to allow it
        if (
            all(
                (
                    isinstance(value, ThreatcodeString)
                    and len(value) > 1
                    and value.startswith(SpecialChars.WILDCARD_MULTI)
                    and value.endswith(SpecialChars.WILDCARD_MULTI)
                    and not value[1:-1].contains_special()
                    for value in detection_item.original_value
                )
            )
            and ThreatcodeContainsModifier not in detection_item.modifiers
        ):
            return [WildcardsInsteadOfContainsModifierIssue([self.rule], detection_item)]
        elif (
            all(
                (
                    isinstance(value, ThreatcodeString)
                    and len(value) > 1
                    and value.startswith(SpecialChars.WILDCARD_MULTI)
                    and not value[1:].contains_special()
                    for value in detection_item.original_value
                )
            )
            and ThreatcodeEndswithModifier not in detection_item.modifiers
        ):
            return [WildcardInsteadOfEndswithIssue([self.rule], detection_item)]
        elif (
            all(
                (
                    isinstance(value, ThreatcodeString)
                    and len(value) > 1
                    and value.endswith(SpecialChars.WILDCARD_MULTI)
                    and not value[:-1].contains_special()
                    for value in detection_item.original_value
                )
            )
            and ThreatcodeStartswithModifier not in detection_item.modifiers
        ):
            return [WildcardInsteadOfStartswithIssue([self.rule], detection_item)]
        else:
            return []


@dataclass
class EscapedWildcardIssue(ThreatcodeValidationIssue):
    description: ClassVar[
        str
    ] = "Rule contains an escaped wildcard in the rule logic. Make sure the escape is intentional."
    severity: ClassVar[ThreatcodeValidationIssueSeverity] = ThreatcodeValidationIssueSeverity.LOW
    string: ThreatcodeString


class EscapedWildcardValidator(ThreatcodeStringValueValidator):
    """Check for the presence of escaped wildcards."""

    wildcard_list = ["*", "?"]

    def validate_value(self, value: ThreatcodeString) -> List[ThreatcodeValidationIssue]:
        if any([x in s for x in self.wildcard_list for s in value if isinstance(s, str)]):
            return [EscapedWildcardIssue(self.rule, value)]
        else:
            return []
