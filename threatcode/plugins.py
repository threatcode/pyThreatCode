import builtins
from dataclasses import dataclass, field
from enum import Enum, auto
import importlib
import importlib.metadata
import inspect
import pkgutil
import re
import subprocess
import sys
from typing import Callable, Dict, Any, List, Optional, Set, Union, get_type_hints
from uuid import UUID
import requests
from packaging.version import Version
from packaging.specifiers import Specifier
import warnings

from threatcode.conversion.base import Backend
from threatcode.pipelines.base import Pipeline
from threatcode.processing.pipeline import ProcessingPipeline
from threatcode.processing.resolver import ProcessingPipelineResolver
from threatcode.rule import EnumLowercaseStringMixin
from threatcode.validators.base import ThreatcodeRuleValidator
import threatcode.backends
import threatcode.pipelines
import threatcode.validators
from threatcode.exceptions import ThreatcodePluginNotFoundError

default_plugin_directory = "https://raw.githubusercontent.com/ThreatcodeHQ/pyThreatcode-plugin-directory/main/pyThreatcode-plugins-v1.json"


@dataclass
class InstalledThreatcodePlugins:
    """Discovery and registrstion of installed backends, pipelines and validator checks as plugins.

    This class represents a set of the objects mentioned above that are available. Further it implements
    autodiscovery of them in the threatcode.backends, threatcode.pipelines and threatcode.validators module namespaces.
    """

    backends: Dict[str, Backend] = field(default_factory=dict)
    pipelines: Dict[str, Callable[[], ProcessingPipeline]] = field(default_factory=dict)
    validators: Dict[str, ThreatcodeRuleValidator] = field(default_factory=dict)

    def register_backend(self, id: str, backend: Backend):
        self.backends[id] = backend

    def register_pipeline(self, id: str, pipeline: Callable[[], ProcessingPipeline]):
        self.pipelines[id] = pipeline

    def register_validator(self, id: str, validator: ThreatcodeRuleValidator):
        self.validators[id] = validator

    @classmethod
    def _discover_module_directories(
        cls, module, directory_name: str, include: bool
    ) -> Dict[str, Any]:
        result = dict()

        def is_pipeline(obj):
            """Checks if an object is a pipeline."""
            return any(
                [
                    inspect.isclass(obj) and issubclass(obj, Pipeline),
                    isinstance(obj, Pipeline),
                    inspect.isfunction(obj)
                    and get_type_hints(obj).get("return") == ProcessingPipeline,
                ]
            )

        def is_validator(obj):
            """Checks if an object is a validator."""
            return (
                inspect.isclass(obj)
                and issubclass(obj, ThreatcodeRuleValidator)
                and obj.__module__ != "threatcode.validators.base"
            )

        def is_backend(obj):
            """Checks if an object is a backend."""
            return inspect.isclass(obj) and issubclass(obj, Backend)

        def is_duplicate(container, klass, name):
            return name in container and container[name] != klass

        if include:
            for mod in pkgutil.iter_modules(module.__path__, module.__name__ + "."):
                # attempt to merge backend directory from module into collected backend directory
                try:
                    imported_module = importlib.import_module(mod.name)
                    submodules: Dict[str, Any] = {}

                    # Skip base, common and test pipelines
                    if imported_module.__name__ in [
                        "threatcode.pipelines.base",
                        "threatcode.pipelines.common",
                    ] or (
                        imported_module.__name__.endswith(".test") and "pytest" not in sys.modules
                    ):
                        continue

                    # Add exported objects to submodules
                    # This is to ensure backwards compatibility with older plugins
                    # that do not use __all__ to export their objects, but instead
                    # rely on gloal variables that map function/class names to objects
                    # The global variable name is the "directory_name" in this case,
                    # which is either "backends", "pipelines" or "validators".
                    if directory_name in imported_module.__dict__:
                        submodules.update(imported_module.__dict__[directory_name])

                    # Look for __all__ at the root (__init__) and
                    # add all objects that are in __all__ :D
                    if "__all__" in imported_module.__dict__:
                        submodules.update(
                            {
                                k: v
                                for k, v in imported_module.__dict__.items()
                                if all(
                                    [
                                        k in imported_module.__dict__["__all__"],
                                        k not in builtins.__dict__,
                                        v not in submodules.values(),
                                    ]
                                )
                            }
                        )
                    # There is no __all__, so add all objects that are not private, not in builtins,
                    # and not already in submodules (to avoid duplicates)
                    else:
                        submodules.update(
                            {
                                k: v
                                for k, v in imported_module.__dict__.items()
                                if not k.startswith("_")
                                and k not in builtins.__dict__
                                and v not in submodules.values()
                            }
                        )

                    # Pipelines and validators reside in submodules
                    if directory_name == "pipelines":
                        for obj_name in submodules:
                            possible_obj = submodules[obj_name]
                            obj_id = obj_name.replace("_pipeline", "")

                            # OR'd condition ensures backwards compatibility with older plugins
                            if is_pipeline(possible_obj) or inspect.isfunction(possible_obj):
                                # Instantiate the pipeline if it is a class.
                                if inspect.isclass(possible_obj) and issubclass(
                                    possible_obj, Pipeline
                                ):
                                    result[obj_id] = possible_obj()
                                else:
                                    result[obj_id] = possible_obj
                    elif directory_name == "validators":
                        for cls_name in submodules:
                            if is_validator(submodules[cls_name]):
                                result[cls_name] = submodules[cls_name]
                    elif directory_name == "backends":
                        # Backends reside on the module level
                        for cls_name in imported_module.__dict__:
                            klass = getattr(imported_module, cls_name)
                            identifier = InstalledThreatcodePlugins._get_backend_identifier(
                                klass, cls_name
                            )
                            if is_backend(klass):
                                if is_duplicate(result, klass, identifier):
                                    # If there is a duplicate, use the class name instead.
                                    # This prevents the backend from being overwritten.
                                    warnings.warn(
                                        f"The '{klass.__name__}' wanted to overwrite the class '{result[identifier].__name__}' registered as '{identifier}'. Consider setting the 'identifier' attribute on the '{result[identifier].__name__}'. Ignoring the '{klass.__name__}'.",
                                    )
                                else:
                                    # Ignore duplicate backends.
                                    result.update({identifier: klass})
                    else:
                        raise ValueError(
                            f"Unknown directory name {directory_name} for module {mod.name}"
                        )
                except KeyError:
                    pass
        return result

    @classmethod
    def autodiscover(
        cls,
        include_backends: bool = True,
        include_pipelines: bool = True,
        include_validators: bool = True,
    ):
        """Automatically discovers backends, pipelines and validators in their corresponding module
        namespaces and return a InstalledThreatcodePlugins class containing all identified classes and generators.
        """
        backends = cls._discover_module_directories(threatcode.backends, "backends", include_backends)
        pipelines = cls._discover_module_directories(
            threatcode.pipelines, "pipelines", include_pipelines
        )
        validators = cls._discover_module_directories(
            threatcode.validators, "validators", include_validators
        )

        return cls(backends, pipelines, validators)

    def get_pipeline_resolver(self) -> ProcessingPipelineResolver:
        """Returns a ProcessingPipelineResolver object with all discovered pipelines."""
        return ProcessingPipelineResolver(
            {
                identifier: pipeline_generator
                for identifier, pipeline_generator in self.pipelines.items()
            }
        )

    @staticmethod
    def _get_backend_identifier(obj: Any, default: str) -> Optional[str]:
        """
        Get the identifier of a backend object. This is either the identifier attribute of
        the object, the __identifier__ attribute of the object, or the __class__ attribute
        of the object. The identifier is then converted to snake_case. If the identifier is
        empty, the default is returned.

        Args:
            obj: The Backend object to get the identifier from.
            default: The default identifier to return if no identifier could be found.

        Returns:
            The identifier of the backend object in snake_case or the default identifier.
        """

        def removesuffix(base: str, suffix: str) -> str:
            """Removes the suffix from the string if it exists.
            This is a backport of the Python 3.9 removesuffix method.
            """
            if base.endswith(suffix):
                return base[: len(base) - len(suffix)]
            return base

        try:
            # 1. Try to get the obj.identifier attribute.
            identifier = getattr(obj, "identifier", None)

            # 2. Try to get the obj.__identifier__ attribute.
            if not identifier:
                identifier = getattr(obj, "__identifier__", None)

            # 3. Try to get the obj.__name__ attribute.
            if not identifier:
                identifier = getattr(obj, "__name__", None)

            # 4. Convert the name to snake_case.
            if identifier:
                identifier = removesuffix(identifier, "Backend")
                identifier = removesuffix(identifier, "backend")
                identifier = removesuffix(identifier, "_")
                words = re.findall(r"[A-Z](?:[A-Z]*(?![a-z])|[a-z]*)", identifier)
                if len(words) == 0:
                    return identifier.lower()
                rebuilt_identifier = "_".join(words).lower()
                # 5. If we still have the "base" backend, return the module identifier instead.
                if rebuilt_identifier == "base":
                    return obj.__module__.split(".")[-1].lower()
                return rebuilt_identifier
            else:
                # 6. If we still don't have an identifier, return the default.
                return default
        except Exception:
            # 7. If anything goes wrong, return the default.
            return default


class ThreatcodePluginType(EnumLowercaseStringMixin, Enum):
    BACKEND = auto()
    PIPELINE = auto()
    VALIDATOR = auto()


class ThreatcodePluginState(EnumLowercaseStringMixin, Enum):
    STABLE = auto()
    TESTING = auto()
    DEVEL = auto()
    BROKEN = auto()
    ORPHANED = auto()


@dataclass
class ThreatcodePlugin:
    """Threatcode plugin description corresponding to https://github.com/ThreatcodeHQ/pyThreatcode-plugin-directory#format"""

    uuid: UUID
    type: ThreatcodePluginType
    id: str
    description: str
    package: str
    project_url: str
    report_issue_url: str
    state: ThreatcodePluginState
    pythreatcode_version: Specifier

    @classmethod
    def from_dict(cls, d: Dict) -> "ThreatcodePlugin":
        """Construct a ThreatcodePlugin object from a dict that results in parsing a plugin description
        from the JSON format linked above."""
        kwargs = {k.replace("-", "_"): v for k, v in d.items()}
        kwargs["uuid"] = UUID(kwargs["uuid"])
        kwargs["pythreatcode_version"] = Specifier(kwargs["pythreatcode_version"])
        kwargs["type"] = ThreatcodePluginType[kwargs["type"].upper()]
        kwargs["state"] = ThreatcodePluginState[kwargs["state"].upper()]

        return cls(**kwargs)

    def is_compatible(self) -> Optional[bool]:
        """Checks if the pyThreatcode version specifier of the plugin matches the used pyThreatcode
        version. Returns None if current version can't be determined, e.g. if pyThreatcode was not
        installed as package."""
        try:
            pythreatcode_version = Version(importlib.metadata.version("pythreatcode"))
            return pythreatcode_version in self.pythreatcode_version
        except importlib.metadata.PackageNotFoundError:
            return None

    def install(self):
        """Install plugin with pip."""
        if sys.prefix == sys.base_prefix:  # not in a virtual environment
            subprocess.check_call(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "-q",
                    "--disable-pip-version-check",
                    "install",
                    self.package,
                ]
            )
        else:
            subprocess.check_call(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "-q",
                    "--disable-pip-version-check",
                    "install",
                    "--no-user",
                    self.package,
                ]
            )

    def uninstall(self):
        """Uninstall plugin with pip."""
        subprocess.check_call([sys.executable, "-m", "pip", "-q", "uninstall", "-y", self.package])


@dataclass
class ThreatcodePluginDirectory:
    """A directory of pyThreatcode plugins that can be loaded from the pyThreatcode-plugin-directory
    repository or an arbitrary location."""

    plugins: Dict[UUID, ThreatcodePlugin] = field(default_factory=dict)
    note: Optional[str] = None

    def register_plugin(self, plugin: ThreatcodePlugin):
        self.plugins[plugin.uuid] = plugin

    @classmethod
    def from_dict(cls, d: Dict):
        return cls(
            plugins={
                UUID(uuid): ThreatcodePlugin.from_dict({"uuid": uuid, **plugin_dict})
                for uuid, plugin_dict in d["plugins"].items()
            },
            note=d.get("note", None),
        )

    @classmethod
    def from_url(cls, url: str, *args, **kwargs) -> "ThreatcodePluginDirectory":
        """Loads the plugin directory from an arbitrary location. All further
        arguments are passed to requests.get()."""
        response = requests.get(url, *args, **kwargs)
        response.raise_for_status()
        return cls.from_dict(response.json())

    @classmethod
    def default_plugin_directory(cls, *args, **kwargs) -> "ThreatcodePluginDirectory":
        """Loads the plugin directory from the pyThreatcode-plugin-directory repository. All further
        arguments are passed to requests.get()."""
        return cls.from_url(default_plugin_directory, *args, **kwargs)

    def plugin_count(self):
        return len(self.plugins)

    def get_plugins(
        self,
        plugin_types: Set[ThreatcodePluginType] = {t for t in ThreatcodePluginType},
        plugin_states: Set[ThreatcodePluginState] = {s for s in ThreatcodePluginState},
        compatible_only: bool = False,
    ) -> List[ThreatcodePlugin]:
        """Return a list of plugins with the specified type and state. Returns all plugins if not specified."""
        return [
            plugin
            for plugin in self.plugins.values()
            if plugin.type in plugin_types
            and plugin.state in plugin_states
            and (not compatible_only or bool(plugin.is_compatible()))
        ]

    def get_plugin_by_uuid(self, uuid: Union[str, UUID]) -> ThreatcodePlugin:
        if isinstance(uuid, str):
            uuid = UUID(uuid)
        try:
            return self.plugins[uuid]
        except KeyError:
            raise ThreatcodePluginNotFoundError(f"Plugin with UUID {uuid} not found")

    def get_plugin_by_id(self, id: str) -> ThreatcodePlugin:
        for plugin in self.plugins.values():
            if plugin.id == id:
                return plugin
        raise ThreatcodePluginNotFoundError(f"Plugin with identifier {id} not found")
