from abc import abstractmethod
from dataclasses import dataclass
import json
from typing import Any, Dict, List, Literal, Optional

import yaml
import threatcode
from threatcode.exceptions import ThreatcodeConfigurationError

from threatcode.processing.templates import TemplateBase


@dataclass
class Finalizer:
    """Conversion output transformation base class."""

    @classmethod
    def from_dict(cls, d: dict) -> "Finalizer":
        try:
            return cls(**d)
        except TypeError as e:
            raise ThreatcodeConfigurationError("Error in instantiation of finalizer: " + str(e))

    @abstractmethod
    def apply(
        self, pipeline: "threatcode.processing.pipeline.ProcessingPipeline", queries: List[Any]
    ) -> Any:
        """Finalize output by applying a transformation to the list of generated and postprocessed queries.

        :param pipeline: Processing pipeline this transformation was contained.
        :type pipeline: threatcode.processing.pipeline.ProcessingPipeline
        :param queries: List of converted and postprocessed queries that should be finalized.
        :type queries: List[Any]
        :return: Output that can be used in further processing of the conversion result.
        :rtype: Any
        """


@dataclass
class ConcatenateQueriesFinalizer(Finalizer):
    """Concatenate queries with a given separator and embed result within a prefix or suffix
    string."""

    separator: str = "\n"
    prefix: str = ""
    suffix: str = ""

    def apply(
        self, pipeline: "threatcode.processing.pipeline.ProcessingPipeline", queries: List[str]
    ) -> str:
        return self.prefix + self.separator.join(queries) + self.suffix


@dataclass
class JSONFinalizer(Finalizer):
    indent: Optional[int] = None

    def apply(
        self, pipeline: "threatcode.processing.pipeline.ProcessingPipeline", queries: List[Any]
    ) -> str:
        return json.dumps(queries, indent=self.indent)


@dataclass
class YAMLFinalizer(Finalizer):
    indent: Optional[int] = None

    def apply(
        self, pipeline: "threatcode.processing.pipeline.ProcessingPipeline", queries: List[Any]
    ) -> str:
        yaml.safe_dump(queries, indent=self.indent)


@dataclass
class TemplateFinalizer(Finalizer, TemplateBase):
    """Apply Jinja2 template provided as template object variable to the queries. The following
    variables are available in the context:

    * queries: all post-processed queries generated by the backend.
    * pipeline: the Threatcode processing pipeline where this transformation is applied including all
      current state information in pipeline.state.

    if *path* is given, *template* is considered as a relative path to a template file below the
    specified path. If it is not provided, the template is specified as plain string. *autoescape*
    controls the Jinja2 HTML/XML auto-escaping.
    """

    def apply(
        self, pipeline: "threatcode.processing.pipeline.ProcessingPipeline", queries: List[Any]
    ) -> str:
        return self.j2template.render(queries=queries, pipeline=pipeline)


finalizers: Dict[str, Finalizer] = {
    "concat": ConcatenateQueriesFinalizer,
    "json": JSONFinalizer,
    "yaml": YAMLFinalizer,
    "template": TemplateFinalizer,
}
