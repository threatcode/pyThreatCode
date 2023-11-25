import re
from collections import Counter
from collections import defaultdict
from dataclasses import dataclass
from typing import ClassVar, Dict, List, Set
from uuid import UUID

from threatcode.rule import ThreatcodeRule
from threatcode.validators.base import (
    ThreatcodeRuleValidator,
    ThreatcodeValidationIssue,
    ThreatcodeValidationIssueSeverity,
)


def is_uuid_v4(val: str) -> bool:
    try:
        id = UUID(str(val))
        if id.version == 4:
            return True
        else:
            return False
    except ValueError:
        return False


@dataclass
class IdentifierExistenceIssue(ThreatcodeValidationIssue):
    description = "Rule has no identifier (UUID)"
    severity = ThreatcodeValidationIssueSeverity.MEDIUM


class IdentifierExistenceValidator(ThreatcodeRuleValidator):
    """Checks if rule has identifier."""

    def validate(self, rule: ThreatcodeRule) -> List[ThreatcodeValidationIssue]:
        if rule.id is None:
            return [IdentifierExistenceIssue([rule])]
        else:
            return []


@dataclass
class IdentifierCollisionIssue(ThreatcodeValidationIssue):
    description: ClassVar[str] = "Rule identifier used by multiple rules"
    severity: ClassVar[ThreatcodeValidationIssueSeverity] = ThreatcodeValidationIssueSeverity.HIGH
    identifier: UUID


class IdentifierUniquenessValidator(ThreatcodeRuleValidator):
    """Check rule UUID uniqueness."""

    ids: Dict[UUID, List[ThreatcodeRule]]

    def __init__(self):
        self.ids = defaultdict(list)

    def validate(self, rule: ThreatcodeRule) -> List[ThreatcodeValidationIssue]:
        if rule.id is not None:
            self.ids[rule.id].append(rule)
        return []

    def finalize(self) -> List[ThreatcodeValidationIssue]:
        return [
            IdentifierCollisionIssue(rules, id) for id, rules in self.ids.items() if len(rules) > 1
        ]


@dataclass
class TitleLengthIssue(ThreatcodeValidationIssue):
    description = "Rule has a title longer than 100 characters"
    severity = ThreatcodeValidationIssueSeverity.MEDIUM


class TitleLengthValidator(ThreatcodeRuleValidator):
    """Checks if rule has a title length longer than 100."""

    def validate(self, rule: ThreatcodeRule) -> List[ThreatcodeValidationIssue]:
        if len(rule.title) > 100:
            return [TitleLengthIssue([rule])]
        else:
            return []


@dataclass
class DuplicateTitleIssue(ThreatcodeValidationIssue):
    description: ClassVar[str] = "Rule title used by multiple rules"
    severity: ClassVar[ThreatcodeValidationIssueSeverity] = ThreatcodeValidationIssueSeverity.HIGH
    title: str


class DuplicateTitleValidator(ThreatcodeRuleValidator):
    """Check rule title uniqueness."""

    titles: Dict[str, List[ThreatcodeRule]]

    def __init__(self):
        self.titles = defaultdict(list)

    def validate(self, rule: ThreatcodeRule) -> List[ThreatcodeValidationIssue]:
        if rule.title is not None:
            self.titles[rule.title].append(rule)
        return []

    def finalize(self) -> List[ThreatcodeValidationIssue]:
        return [
            DuplicateTitleIssue(rules, title)
            for title, rules in self.titles.items()
            if len(rules) > 1
        ]


@dataclass
class DuplicateReferencesIssue(ThreatcodeValidationIssue):
    description = "The same references appears multiple times"
    severity = ThreatcodeValidationIssueSeverity.MEDIUM
    reference: str


class DuplicateReferencesValidator(ThreatcodeRuleValidator):
    """Validate rule References uniqueness."""

    def validate(self, rule: ThreatcodeRule) -> List[ThreatcodeValidationIssue]:
        references = Counter(rule.references)
        return [
            DuplicateReferencesIssue([rule], reference)
            for reference, count in references.items()
            if count > 1
        ]


@dataclass
class StatusExistenceIssue(ThreatcodeValidationIssue):
    description = "Rule has no status"
    severity = ThreatcodeValidationIssueSeverity.MEDIUM


class StatusExistenceValidator(ThreatcodeRuleValidator):
    """Checks if rule has a status."""

    def validate(self, rule: ThreatcodeRule) -> List[ThreatcodeValidationIssue]:
        if rule.status is None:
            return [StatusExistenceIssue([rule])]
        else:
            return []


@dataclass
class StatusUnsupportedIssue(ThreatcodeValidationIssue):
    description = "Rule has UNSUPPORTED status"
    severity = ThreatcodeValidationIssueSeverity.MEDIUM


class StatusUnsupportedValidator(ThreatcodeRuleValidator):
    """Checks if rule has a status UNSUPPORTED."""

    def validate(self, rule: ThreatcodeRule) -> List[ThreatcodeValidationIssue]:
        if rule.status and rule.status.name == "UNSUPPORTED":
            return [StatusUnsupportedIssue([rule])]
        else:
            return []


@dataclass
class DateExistenceIssue(ThreatcodeValidationIssue):
    description = "Rule has no date"
    severity = ThreatcodeValidationIssueSeverity.MEDIUM


class DateExistenceValidator(ThreatcodeRuleValidator):
    """Checks if rule has a data."""

    def validate(self, rule: ThreatcodeRule) -> List[ThreatcodeValidationIssue]:
        if rule.date is None:
            return [DateExistenceIssue([rule])]
        else:
            return []


@dataclass
class DuplicateFilenameIssue(ThreatcodeValidationIssue):
    description: ClassVar[str] = "Rule filemane used by multiple rules"
    severity: ClassVar[ThreatcodeValidationIssueSeverity] = ThreatcodeValidationIssueSeverity.HIGH
    filename: str


class DuplicateFilenameValidator(ThreatcodeRuleValidator):
    """Check rule filename uniqueness."""

    filenames: Dict[str, List[ThreatcodeRule]]

    def __init__(self):
        self.filenames = defaultdict(list)

    def validate(self, rule: ThreatcodeRule) -> List[ThreatcodeValidationIssue]:
        if rule.source is not None:
            self.filenames[rule.source.path.name].append(rule)
        return []

    def finalize(self) -> List[ThreatcodeValidationIssue]:
        return [
            DuplicateFilenameIssue(rules, filename)
            for filename, rules in self.filenames.items()
            if len(rules) > 1
        ]


@dataclass
class FilenameThreatcodeIssue(ThreatcodeValidationIssue):
    description: ClassVar[str] = "Rule filemane doesn't match ThreatcodeHQ standard"
    severity: ClassVar[ThreatcodeValidationIssueSeverity] = ThreatcodeValidationIssueSeverity.HIGH
    filename: str


class FilenameThreatcodeValidator(ThreatcodeRuleValidator):
    """Check rule filename match ThreatcodeHQ standard."""

    def validate(self, rule: ThreatcodeRule) -> List[ThreatcodeValidationIssue]:
        filename_pattern = re.compile(r"[a-z0-9_]{10,90}\.yml")
        if rule.source is not None:
            filename = rule.source.path.name
            if filename_pattern.match(filename) is None or not "_" in filename:
                return [FilenameThreatcodeIssue(rule, filename)]
        return []


@dataclass
class FilenameLenghIssue(ThreatcodeValidationIssue):
    description: ClassVar[str] = "Rule filename is too short or long"
    severity: ClassVar[ThreatcodeValidationIssueSeverity] = ThreatcodeValidationIssueSeverity.HIGH
    filename: str


class FilenameLenghValidator(ThreatcodeRuleValidator):
    """Check rule filename lengh"""

    def validate(self, rule: ThreatcodeRule) -> List[ThreatcodeValidationIssue]:
        if rule.source is not None:
            filename = rule.source.path.name
            if len(filename) < 10 or len(filename) > 90:
                return [FilenameLenghIssue(rule, filename)]
        return []


@dataclass
class CustomAttributesIssue(ThreatcodeValidationIssue):
    description: ClassVar[str] = "Rule use optional field name similar to legit"
    severity: ClassVar[ThreatcodeValidationIssueSeverity] = ThreatcodeValidationIssueSeverity.MEDIUM
    fieldname: str


class CustomAttributesValidator(ThreatcodeRuleValidator):
    """Check if field name is similar to legit one"""

    known_custom_attributes: Set[str] = {
        "realted",
        "relatde",
        "relted",
        "rlated",
        "reference",
    }

    def validate(self, rule: ThreatcodeRule) -> List[ThreatcodeValidationIssue]:
        if rule.custom_attributes is not None:
            for k in rule.custom_attributes.keys():
                if k in self.known_custom_attributes:
                    return [CustomAttributesIssue(rule, k)]
        return []


@dataclass
class DescriptionExistenceIssue(ThreatcodeValidationIssue):
    description = "Rule has no description"
    severity = ThreatcodeValidationIssueSeverity.MEDIUM


class DescriptionExistenceValidator(ThreatcodeRuleValidator):
    """Checks if rule has a description."""

    def validate(self, rule: ThreatcodeRule) -> List[ThreatcodeValidationIssue]:
        if rule.description is None:
            return [DescriptionExistenceIssue([rule])]
        else:
            return []


@dataclass
class DescriptionLengthIssue(ThreatcodeValidationIssue):
    description = "Rule has a too short description"
    severity = ThreatcodeValidationIssueSeverity.MEDIUM


class DescriptionLengthValidator(ThreatcodeRuleValidator):
    """Checks if rule has a description."""

    def validate(self, rule: ThreatcodeRule) -> List[ThreatcodeValidationIssue]:
        if rule.description is not None and len(rule.description) < 16:
            return [DescriptionLengthIssue([rule])]
        else:
            return []


@dataclass
class LevelExistenceIssue(ThreatcodeValidationIssue):
    description = "Rule has no level"
    severity = ThreatcodeValidationIssueSeverity.MEDIUM


class LevelExistenceValidator(ThreatcodeRuleValidator):
    """Checks if rule has a level."""

    def validate(self, rule: ThreatcodeRule) -> List[ThreatcodeValidationIssue]:
        if rule.level is None:
            return [LevelExistenceIssue([rule])]
        else:
            return []
