from dataclasses import dataclass
from typing import ClassVar, Counter, List, Set, Type
from threatcode.modifiers import (
    ThreatcodeAllModifier,
    ThreatcodeBase64Modifier,
    ThreatcodeBase64OffsetModifier,
    ThreatcodeContainsModifier,
    ThreatcodeModifier,
)
from threatcode.rule import ThreatcodeDetectionItem
from threatcode.validators.base import (
    ThreatcodeDetectionItemValidator,
    ThreatcodeValidationIssue,
    ThreatcodeValidationIssueSeverity,
)


@dataclass
class AllWithoutContainsModifierIssue(ThreatcodeValidationIssue):
    description: ClassVar[
        str
    ] = "A field-bound 'all' modifier without 'contains' modifier doesn't matches anything"
    severity: ClassVar[ThreatcodeValidationIssueSeverity] = ThreatcodeValidationIssueSeverity.HIGH
    detection_item: ThreatcodeDetectionItem


@dataclass
class Base64OffsetWithoutContainsModifierIssue(ThreatcodeValidationIssue):
    description: ClassVar[
        str
    ] = "A 'base64offset' modifier must be followed by a 'contains' modifier, because calculated values will be prefixed/suffixed with further characters."
    severity: ClassVar[ThreatcodeValidationIssueSeverity] = ThreatcodeValidationIssueSeverity.HIGH
    detection_item: ThreatcodeDetectionItem


@dataclass
class ModifierAppliedMultipleIssue(ThreatcodeValidationIssue):
    description: ClassVar[str] = "Modifiers shouldn't be applied multiple times"
    severity: ClassVar[ThreatcodeValidationIssueSeverity] = ThreatcodeValidationIssueSeverity.MEDIUM
    detection_item: ThreatcodeDetectionItem
    modifiers: Set[Type[ThreatcodeModifier]]


class InvalidModifierCombinationsValidator(ThreatcodeDetectionItemValidator):
    """Detects invalid combinations of value modifiers."""

    def validate_detection_item(
        self, detection_item: ThreatcodeDetectionItem
    ) -> List[ThreatcodeValidationIssue]:
        issues = []

        # Check for 'all' without 'contains' modifier
        if (
            detection_item.field is not None
            and ThreatcodeAllModifier in detection_item.modifiers
            and ThreatcodeContainsModifier not in detection_item.modifiers
        ):
            issues.append(AllWithoutContainsModifierIssue([self.rule], detection_item))

        # Check for 'base64offset' without 'contains' modifier
        if (
            ThreatcodeBase64OffsetModifier in detection_item.modifiers
            and ThreatcodeContainsModifier not in detection_item.modifiers
        ):
            issues.append(Base64OffsetWithoutContainsModifierIssue([self.rule], detection_item))

        # Check for multiple appliance of modifiers
        mod_count = Counter(detection_item.modifiers)
        multiple_modifiers = {
            mod
            for mod, count in mod_count.items()
            if (count > 1 and mod not in {ThreatcodeBase64Modifier})  # allowlist
        }
        if multiple_modifiers:
            issues.append(
                ModifierAppliedMultipleIssue([self.rule], detection_item, multiple_modifiers)
            )

        return issues
