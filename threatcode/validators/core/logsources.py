from dataclasses import dataclass, field
from typing import ClassVar, Dict, List, Tuple
from threatcode.rule import ThreatcodeDetectionItem, ThreatcodeRule
from threatcode.types import ThreatcodeNumber

from threatcode.validators.base import (
    ThreatcodeDetectionItemValidator,
    ThreatcodeValidationIssue,
    ThreatcodeValidationIssueSeverity,
)
from threatcode.rule import ThreatcodeLogSource

specific_to_generic_logsource_mapping: Dict[str, Tuple[ThreatcodeLogSource, Dict[int, str]]] = {
    # "Sysmon": (ThreatcodeLogSource(None, None, "sysmon"), {
    ThreatcodeLogSource(None, "windows", "sysmon"): {
        1: "process_creation",
        2: "file_change",
        3: "network_connection",
        5: "process_termination",
        4: "sysmon_status",
        6: "driver_load",
        7: "image_load",
        8: "create_remote_thread",
        9: "raw_access_thread",
        10: "process_access",
        11: "file_event",
        12: "registry_add",
        12: "registry_delete",
        13: "registry_set",
        14: "registry_rename",
        12: "registry_event",
        13: "registry_event",
        14: "registry_event",
        15: "create_stream_hash",
        16: "sysmon_status",
        17: "pipe_created",
        18: "pipe_created",
        19: "wmi_event",
        20: "wmi_event",
        21: "wmi_event",
        22: "dns_query",
        23: "file_delete",
        26: "file_delete",
        24: "clipboard_change",
        25: "process_tampering",
        26: "file_delete_detected",
        27: "file_block_executable",
        28: "file_block_shredding",
        29: "file_executable_detected",
        255: "sysmon_error",
    },
    ThreatcodeLogSource(None, "windows", "security"): {
        4688: "process_creation",
    },
}


@dataclass
class SpecificInsteadOfGenericLogsourceIssue(ThreatcodeValidationIssue):
    description: ClassVar[str] = "Usage of specific instead of generic log source"
    severity: ClassVar[ThreatcodeValidationIssueSeverity] = ThreatcodeValidationIssueSeverity.HIGH
    logsource: ThreatcodeLogSource
    event_id: int
    generic_logsource: ThreatcodeLogSource


class SpecificInsteadOfGenericLogsourceValidator(ThreatcodeDetectionItemValidator):
    """Identify usage of specific Windows event identifiers where corresponding generic log sources exist."""

    def validate(self, rule: ThreatcodeRule) -> List[ThreatcodeValidationIssue]:
        for (
            logsource,
            eventid_mappings,
        ) in specific_to_generic_logsource_mapping.items():
            if rule.logsource in logsource:
                self.logsource = logsource
                self.eventid_mappings = eventid_mappings
                self.disallowed_logsource_event_ids = eventid_mappings.keys()
                return super().validate(rule)
        return []

    def validate_detection_item(
        self, detection_item: ThreatcodeDetectionItem
    ) -> List[ThreatcodeValidationIssue]:
        if detection_item.field == "EventID":
            return [
                SpecificInsteadOfGenericLogsourceIssue(
                    rules=[self.rule],
                    logsource=self.logsource,
                    event_id=event_id.number,
                    generic_logsource=ThreatcodeLogSource(self.eventid_mappings[event_id.number]),
                )
                for event_id in detection_item.value
                if isinstance(event_id, ThreatcodeNumber)
                and event_id.number in self.disallowed_logsource_event_ids
            ]
        else:
            return []
