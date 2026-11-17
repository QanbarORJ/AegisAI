"""Decorator-based Security Test Plugin Registry for the AegisAI Assessment Engine.

Implements ARCHITECTURE.md Section 3 & 4 and ROADMAP.md Phase 3 deliverables.
"""

from collections.abc import Sequence

from app.engine.contracts import BaseSecurityTest


class SecurityTestRegistry:
    """Centralized registry managing discovery, lookup, and module/architecture filtering of security tests."""

    def __init__(self) -> None:
        self._tests: dict[str, type[BaseSecurityTest]] = {}

    def register(
        self,
        test_cls: type[BaseSecurityTest],
        *,
        allow_override: bool = False,
    ) -> type[BaseSecurityTest]:
        """Register a BaseSecurityTest subclass by its canonical `test_id`."""
        if not isinstance(test_cls, type) or not issubclass(test_cls, BaseSecurityTest):
            raise TypeError(
                f"Plugin '{test_cls}' must inherit from BaseSecurityTest."
            )
        test_id = getattr(test_cls, "test_id", "").strip()
        if not test_id:
            raise ValueError(
                f"Plugin class '{test_cls.__name__}' must define a non-empty 'test_id'."
            )
        existing = self._tests.get(test_id)
        if existing is not None and existing is not test_cls and not allow_override:
            raise ValueError(
                f"Duplicate test_id '{test_id}' is already registered by '{existing.__name__}'."
            )
        self._tests[test_id] = test_cls
        return test_cls

    def unregister(self, test_id: str) -> None:
        """Remove a registered test by ID (primarily for isolated testing)."""
        self._tests.pop(test_id, None)

    def clear(self) -> None:
        """Clear all registered tests from this registry instance."""
        self._tests.clear()

    def get(self, test_id: str) -> BaseSecurityTest | None:
        """Instantiate and return a registered test plugin by `test_id`."""
        cls = self._tests.get(test_id)
        return cls() if cls is not None else None

    def list_all(self) -> list[BaseSecurityTest]:
        """Return instantiated plugins for all registered tests sorted by `test_id`."""
        return [self._tests[k]() for k in sorted(self._tests.keys())]

    def get_tests_for_assessment(
        self,
        *,
        selected_modules: Sequence[str] | None = None,
        architecture_type: str | None = None,
        include_non_applicable: bool = False,
    ) -> list[BaseSecurityTest]:
        """Filter registered tests by selected modules and optionally by target architecture."""
        normalized_modules = (
            {m.strip().upper() for m in selected_modules if m and m.strip()}
            if selected_modules
            else None
        )
        arch = architecture_type.strip().upper() if architecture_type else None

        matched: list[BaseSecurityTest] = []
        config_audit_test_ids = {
            "LLM-SPE-001",
            "LLM-CFG-001",
            "RAG-ARCH-001",
            "AGT-PERM-001",
        }
        for test_id in sorted(self._tests.keys()):
            plugin = self._tests[test_id]()
            if normalized_modules:
                mod_upper = plugin.module.upper()
                matches_mod = mod_upper in normalized_modules or (
                    "CONFIG" in normalized_modules and test_id in config_audit_test_ids
                )
                if not matches_mod:
                    continue

            if (
                not include_non_applicable
                and arch
                and arch != "HYBRID"
                and plugin.applicable_architectures
                and arch not in [a.upper() for a in plugin.applicable_architectures]
            ):
                continue

            matched.append(plugin)

        return matched

    @property
    def registered_ids(self) -> list[str]:
        """Return sorted list of registered test IDs."""
        return sorted(self._tests.keys())


# Global default plugin registry
default_registry = SecurityTestRegistry()


def register_security_test(
    test_cls: type[BaseSecurityTest] | None = None,
    *,
    registry: SecurityTestRegistry | None = None,
):
    """Class decorator that registers a BaseSecurityTest plugin in the SecurityTestRegistry.

    Supports both `@register_security_test` and `@register_security_test(registry=custom_registry)`.
    """
    target_registry = registry or default_registry

    def _decorator(cls: type[BaseSecurityTest]) -> type[BaseSecurityTest]:
        return target_registry.register(cls)

    if test_cls is not None:
        return _decorator(test_cls)
    return _decorator
