from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from pyparsing import List


@dataclass
class ThreatcodeRuleLocation:
    """Describes a Threatcode source file and optionally a location inside it."""

    path: Path
    line: Optional[int] = None
    char: Optional[int] = None

    def __post_init__(self):
        if isinstance(self.path, str):
            self.path = Path(self.path)

    def __str__(self):
        s = str(self.path.resolve())
        if self.line is not None:
            s += ":" + str(self.line)
            if self.char is not None:
                s += ":" + str(self.char)
        return s


class ThreatcodeError(ValueError):
    """Generic Threatcode error and super-class of all Threatcode exceptions"""

    def __init__(self, *args, **kwargs):
        try:
            self.source = kwargs["source"]
            del kwargs["source"]
        except KeyError:
            self.source = None
        super().__init__(*args, **kwargs)

    def __str__(self):
        if self.source is not None:
            return super().__str__() + " in " + str(self.source)
        else:
            return super().__str__()

    def __eq__(self, other: object) -> bool:
        try:
            return (
                type(self) is type(other)
                and self.source == other.source
                and self.args == other.args
            )
        except AttributeError:
            return False


class ThreatcodeTitleError(ThreatcodeError):
    """Error in Threatcode rule logosurce specification"""

    pass


class ThreatcodeLogsourceError(ThreatcodeError):
    """Error in Threatcode rule logosurce specification"""

    pass


class ThreatcodeDetectionError(ThreatcodeError):
    """Error in Threatcode rule detection"""

    pass


class ThreatcodeConditionError(ThreatcodeError):
    """Error in Threatcode rule condition"""

    pass


class ThreatcodeIdentifierError(ThreatcodeError):
    """Error in Threatcode rule identifier"""

    pass


class ThreatcodeAuthorError(ThreatcodeError):
    """Error in Threatcode rule author"""

    pass


class ThreatcodeRelatedError(ThreatcodeError):
    """Error in Threatcode rule related"""

    pass


class ThreatcodeDateError(ThreatcodeError):
    """Error in Threatcode rule date"""

    pass


class ThreatcodeModifiedError(ThreatcodeError):
    """Error in Threatcode rule modified"""

    pass


class ThreatcodeDescriptionError(ThreatcodeError):
    """Error in Threatcode rule description"""

    pass


class ThreatcodeReferencesError(ThreatcodeError):
    """Error in Threatcode rule references"""

    pass


class ThreatcodeFieldsError(ThreatcodeError):
    """Error in Threatcode rule fields"""

    pass


class ThreatcodeFalsePositivesError(ThreatcodeError):
    """Error in Threatcode rule falsepositives"""

    pass


class ThreatcodeStatusError(ThreatcodeError):
    """Error in Threatcode rule status"""

    pass


class ThreatcodeLevelError(ThreatcodeError):
    """Error in Threatcode rule level"""

    pass


class ThreatcodeModifierError(ThreatcodeError):
    """Error in Threatcode rule value modifier specification"""

    pass


class ThreatcodeTypeError(ThreatcodeModifierError):
    """Threatcode modifier not applicable on value type"""

    pass


class ThreatcodeValueError(ThreatcodeError):
    """Error in Threatcode rule value"""

    pass


class ThreatcodeRegularExpressionError(ThreatcodeValueError):
    """Error in regular expression contained in Threatcode rule"""

    pass


class ThreatcodePlaceholderError(ThreatcodeValueError):
    """Attempted to convert an unhandled Placeholder into a query"""

    pass


class ThreatcodeCollectionError(ThreatcodeError):
    """Error in Threatcode collection, e.g. unknown action"""

    pass


class ThreatcodeConfigurationError(ThreatcodeError):
    """Error in configuration of a Threatcode processing pipeline"""

    pass


class ThreatcodeFeatureNotSupportedByBackendError(ThreatcodeError):
    """Threatcode feature is not supported by the backend."""

    pass


class ThreatcodePipelineNotFoundError(ThreatcodeError, ValueError):
    """An attempt to resolve a processing pipeline from a specifier failed because it was not
    found."""

    def __init__(self, spec: str, *args, **kwargs):
        self.spec = spec
        super().__init__(*args, **kwargs)

    def __str__(self):
        return f"Processing pipeline '{self.spec}' not found"


class ThreatcodePipelineNotAllowedForBackendError(ThreatcodeConfigurationError):
    """One or multiple processing pipelines doesn't matches the given backend."""

    def __init__(self, spec: str, backend: str, *args, **kwargs):
        self.wrong_pipeline = spec
        self.backend = backend
        super().__init__(*args, **kwargs)

    def __str__(self):
        return (
            f"Processing pipelines not allowed for backend '{self.backend}': {self.wrong_pipeline}"
        )


class ThreatcodeTransformationError(ThreatcodeError):
    """Error while transformation. Can be raised intentionally by FailureTransformation."""


class ThreatcodePluginNotFoundError(ThreatcodeError):
    """Plugin was not found."""
