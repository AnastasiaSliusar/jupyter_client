# Copyright (c) Jupyter Development Team.
# Distributed under the terms of the Modified BSD License.

from __future__ import annotations

import copy
import re
import typing as t

from . import kernelspec

_PLACEHOLDER = re.compile(r"\{([A-Za-z0-9_]+)\}")
_CONNECTION_FILE = "connection_file"

KernelParamType = t.Union[t.List[str], t.Dict[str, str], str]


class ParameterizedKernelSpec:
    """Shared helpers for parameterized kernelspecs."""

    @classmethod
    def get_default_custom_kernel_specs_value(
        cls, kspec: kernelspec.KernelSpec
    ) -> dict[str, t.Any]:
        """Get default values of custom kernel specs."""

        properties = cls._parameter_properties(kspec)
        if not properties:
            return {}

        return {
            name: definition["default"]
            for name, definition in properties.items()
            if isinstance(definition, dict) and "default" in definition
        }

    @staticmethod
    def find_parameters(value: t.Any) -> set[str]:
        """Find custom kernel variables."""
        if not isinstance(value, str):
            return set()

        return {name for name in _PLACEHOLDER.findall(value) if name != _CONNECTION_FILE}

    @classmethod
    def has_custom_parameter(cls, value: t.Any) -> bool:
        return bool(cls.find_parameters(value))

    @classmethod
    def get_argv_env_kernel_variables(cls, kspec: kernelspec.KernelSpec) -> int:
        """Count total custom kernel variables for args and envs together."""
        total = 0

        for value in getattr(kspec, "argv", None) or []:
            total += len(cls.find_parameters(value))

        for value in (getattr(kspec, "env", None) or {}).values():
            total += len(cls.find_parameters(value))

        return total

    @staticmethod
    def substitute_parameters(
        value: t.Any,
        values: dict[str, t.Any],
    ) -> str:
        """Substitute only values that were explicitly resolved."""
        return _PLACEHOLDER.sub(
            lambda match: (
                str(values[match.group(1)]) if match.group(1) in values else match.group(0)
            ),
            value,
        )

    @classmethod
    def format_kernel_cmd(
        cls,
        cmd: t.List[t.Any],
        values: dict[str, t.Any],
    ) -> list[str]:
        """Replace arg custom kernel variables by values."""
        return [cls.substitute_parameters(arg, values) for arg in cmd]

    @classmethod
    def format_kernel_env(
        cls,
        env: t.Dict[str, t.Any],
        values: dict[str, t.Any],
    ) -> dict[str, str]:
        """Replace env custom kernel variables by values."""
        return {key: cls.substitute_parameters(value, values) for key, value in env.items()}

    @staticmethod
    def _parameter_properties(kspec: kernelspec.KernelSpec) -> dict[str, t.Any]:
        """Return properties part of kernel metadata."""

        metadata = getattr(kspec, "metadata", None) or {}
        parameters = metadata.get("parameters", {})
        properties = parameters.get("properties", {})
        return properties if isinstance(properties, dict) else {}

    @classmethod
    def get_count_secure_kernel_variables(
        cls, obj: dict[str, t.Any], counter_secure_kernel_variables: int = 0
    ) -> int:
        """Count secured custom kernel variables."""
        is_secure = True
        if "properties" in obj:
            propetries = obj["properties"].items()
            if len(propetries) > 0:
                for _property_key, property_value in propetries:
                    if (
                        property_value.get("type") == "string"
                        or property_value.get("type") == "null"
                    ):
                        if property_value.get("enum"):
                            counter_secure_kernel_variables = counter_secure_kernel_variables + 1
                        else:
                            is_secure = False
                    elif property_value.get("type") == "array":
                        is_secure = False
                    elif property_value.get("enum"):
                        counter_secure_kernel_variables = counter_secure_kernel_variables + 1
                    elif property_value.get("type") == "object":
                        counter_secure_kernel_variables = cls.get_count_secure_kernel_variables(
                            obj=obj, counter_secure_kernel_variables=counter_secure_kernel_variables
                        )

        if is_secure is False:
            counter_secure_kernel_variables = 0

        return counter_secure_kernel_variables

    @classmethod
    def check_kernel_is_secure(cls, kspec: kernelspec.KernelSpec) -> bool:
        """Return False is kernel spec is not secure."""

        is_secure = False
        total_sum_kernel_variables = cls.get_argv_env_kernel_variables(kspec)

        properties = cls._parameter_properties(kspec)
        if not properties:
            # check if there are kernel variables even metadata.parameters are empty
            if total_sum_kernel_variables > 0:
                is_secure = False
            else:
                is_secure = True
        else:
            counter_secure_kernel_variables = cls.get_count_secure_kernel_variables(
                obj=kspec.metadata["parameters"], counter_secure_kernel_variables=0
            )
            if total_sum_kernel_variables > 0:
                if counter_secure_kernel_variables == total_sum_kernel_variables:
                    is_secure = True
                else:
                    is_secure = False
            else:
                is_secure = False
        return is_secure

    @classmethod
    def replace_by_default(
        cls,
        kspec: kernelspec.KernelSpec,
        kernel_variable: str,
        default_value: t.Any,
    ) -> t.Any:
        """Replaces args and env by default values."""
        result = copy.deepcopy(kspec)

        result.argv = cls.format_kernel_cmd(
            list(result.argv or []),
            {kernel_variable: default_value},
        )

        result.env = cls.format_kernel_env(
            dict(getattr(result, "env", None) or {}),
            {kernel_variable: default_value},
        )

        return result

    @classmethod
    def check_kernel_custom_all_default_values(
        cls, kspec: kernelspec.KernelSpec
    ) -> dict[str, t.Any]:
        """Check whether there are default values for all custom kernel variables."""
        assert kspec is not None
        properties = cls._parameter_properties(kspec)
        if properties:
            has_default = True

            new_kspec = copy.deepcopy(kspec)
            for property_key, property_value in properties.items():
                if isinstance(property_value, dict) and "default" in property_value:
                    new_kspec = cls.replace_by_default(
                        kspec, property_key, property_value["default"]
                    )
                else:
                    has_default = False

            if has_default is False:
                result = {"kspec": new_kspec, "all_have_default": False}
            else:
                # check if there is anything after replacing
                total_sum_kernel_variables = cls.get_argv_env_kernel_variables(kspec=new_kspec)

                if total_sum_kernel_variables > 0:
                    result = {"kspec": new_kspec, "all_have_default": False}
                else:
                    result = {"kspec": new_kspec, "all_have_default": True}
        else:
            result = {"kspec": kspec, "all_have_default": False}
        return result

    @classmethod
    def check_parameterized_kernel(
        cls,
        kspec: kernelspec.KernelSpec,
        allow_insecure_kernelspec_params: bool = False,
    ) -> t.Any | None:
        """Apply the security policy and default-value fallback."""
        is_secure = cls.check_kernel_is_secure(kspec)

        result = copy.deepcopy(kspec)
        metadata = dict(getattr(result, "metadata", None) or {})
        metadata["is_secure"] = is_secure
        result.metadata = metadata

        if is_secure or allow_insecure_kernelspec_params:
            return result

        fallback = cls.check_kernel_custom_all_default_values(result)
        if fallback["all_have_default"]:
            fallback_spec = fallback["kspec"]
            fallback_metadata = dict(getattr(fallback_spec, "metadata", None) or {})
            fallback_metadata["is_secure"] = False
            fallback_spec.metadata = fallback_metadata
            return fallback_spec
        else:
            return None

    @classmethod
    def get_custom_kernel_spec_value(
        cls, launch_args: t.Dict[str, t.Any], custom_kernel_default_value: dict[str, t.Any]
    ) -> dict[str, t.Any]:
        """Get value for a custom kernel variable. In case it is not present it takes its default value."""
        custom_kernel_dict = {}
        if "custom_kernel_specs" in launch_args:
            custom_kernel_specs = launch_args["custom_kernel_specs"].copy()
            custom_kernel_dict = (
                custom_kernel_specs.copy() if isinstance(custom_kernel_specs, dict) else {}
            )

            # check is custom kernel variables are full if not then we should take default ones
            if custom_kernel_default_value:
                for key, value in custom_kernel_default_value.items():
                    if key not in custom_kernel_dict:
                        custom_kernel_dict[key] = value
        elif custom_kernel_default_value:
            # if not but default values are present into a kernel.json file then we have to take them
            custom_kernel_dict = custom_kernel_default_value.copy()
        return custom_kernel_dict

    @classmethod
    def clear_custom_kernel_parameters(cls, kernel_parameters: t.Any) -> KernelParamType:
        """
        Safely removes unresolved custom kernel variables.
        """
        if isinstance(kernel_parameters, list):
            clean_parameters = [
                item
                for item in kernel_parameters
                if item != "" and not cls.has_custom_parameter(item)
            ]

            return clean_parameters if clean_parameters else kernel_parameters
        elif isinstance(kernel_parameters, dict):
            clean_parameters = {
                key: value
                for key, value in kernel_parameters.items()
                if value != "" and not cls.has_custom_parameter(value)
            }

            return clean_parameters if clean_parameters else kernel_parameters
        else:
            if isinstance(kernel_parameters, str):
                if kernel_parameters == "" or cls.has_custom_parameter(kernel_parameters):
                    return ""
                return kernel_parameters

        return kernel_parameters

    @classmethod
    def update_custom_env_parameters(
        cls,
        launch_args: t.Dict[str, t.Any],
        custom_kernel_default_value: dict[str, t.Any],
        env: t.Dict[str, str],
    ) -> KernelParamType:
        """Replace custom kernel variables in env."""
        custom_kernel_dict = cls.get_custom_kernel_spec_value(
            launch_args, custom_kernel_default_value
        )
        newEnv = cls.format_kernel_env(env, custom_kernel_dict)
        return cls.clear_custom_kernel_parameters(newEnv)

    @classmethod
    def update_custom_arg_parameters(
        cls, kpecs: kernelspec.KernelSpec, cmd: t.List[t.Any], kwargs: t.Dict[str, t.Any]
    ) -> KernelParamType:
        """Replace custom kernel variables in args."""
        custom_kernel_default_value = cls.get_default_custom_kernel_specs_value(kpecs)

        custom_kernel_dict = cls.get_custom_kernel_spec_value(kwargs, custom_kernel_default_value)
        newArgs = cls.format_kernel_cmd(cmd, custom_kernel_dict)
        return cls.clear_custom_kernel_parameters(newArgs)
