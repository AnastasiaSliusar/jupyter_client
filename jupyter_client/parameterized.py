

from __future__ import annotations

import copy
import re
import typing as t

_PLACEHOLDER = re.compile(r"\{([A-Za-z0-9_]+)\}")
_CONNECTION_FILE = "connection_file"


class ParameterizedKernelSpec:
    """Shared helpers for parameterized kernelspecs."""

    def get_default_custom_kernel_specs_value(self, kspec: t.Any) -> dict[str, t.Any]:
        """Get default values of custom kernel specs."""

        metadata = getattr(kspec, "metadata", None) or {}
        parameters = metadata.get("parameters", {})
        properties = self._parameter_properties(kspec)
        if not isinstance(properties, dict):
            return {}

        return {
            name: definition["default"]
            for name, definition in properties.items()
            if isinstance(definition, dict) and "default" in definition
        }


    def find_parameters(self, value: t.Any) -> set[str]:
        """Find custom kernel variables."""
        if not isinstance(value, str):
            return set()

        return {
            name
            for name in _PLACEHOLDER.findall(value)
            if name != _CONNECTION_FILE
        }


    def has_custom_parameter(self, value: t.Any) -> bool:
        return bool(self.find_parameters(value))


    def get_argv_env_kernel_variables(self, kspec: t.Any) -> int:
        """Returns the total count of custom kernel variables parameters in argv and env."""
        total_variables_count = 0

        for value in getattr(kspec, "argv", None) or []:
            total_variables_count += len(self.find_parameters(value))
        for value in (getattr(kspec, "env", None) or {}).values():
            total_variables_count += len(self.find_parameters(value))

        return total_variables_count



    def substitute_parameters(
        self,
        value: str,
        values: dict[str, t.Any],
    ) -> str:
        """Substitute only values that were explicitly resolved."""
        return _PLACEHOLDER.sub(
            lambda match: (
                str(values[match.group(1)])
                if match.group(1) in values
                else match.group(0)
            ),
            value,
        )


    def format_kernel_cmd(
        self,
        cmd: list[str],
        values: dict[str, t.Any],
    ) -> list[str]:
        return [
            self.substitute_parameters(arg, values)
            for arg in cmd
        ]


    def format_kernel_env(
        self,
        env: dict[str, str],
        values: dict[str, t.Any],
    ) -> dict[str, str]:
        return {
            key: self.substitute_parameters(value, values)
            for key, value in env.items()
        }

    def _parameter_properties(kspec: t.Any) -> dict[str, t.Any]:
        metadata = getattr(kspec, "metadata", None) or {}
        parameters = metadata.get("parameters", {})
        properties = parameters.get("properties", {})
        return properties if isinstance(properties, dict) else {}

    def get_count_secure_kernel_variables(self,
        obj: dict[str, t.Any],
        counter_secure_kernel_variables: int = 0)-> int:
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
                        counter_secure_kernel_variables = self.get_count_secure_kernel_variables(
                            obj=obj, counter_secure_kernel_variables=counter_secure_kernel_variables
                        )

        if is_secure is False:
            counter_secure_kernel_variables = 0

        return counter_secure_kernel_variables

    def check_kernel_is_secure(self, kspec: t.Any) -> bool:
        is_secure = False
        total_sum_kernel_variables = self.get_argv_env_kernel_variables(kspec)

        properties = self._parameter_properties(kspec)
        if not isinstance(properties, dict):
            # check if there are kernel variables even metadata.parameters are empty
            if total_sum_kernel_variables > 0:
                is_secure = False
            else:
                is_secure = True
        else:
            counter_secure_kernel_variables = self.get_count_secure_kernel_variables(
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


    def replace_by_default(
        self,
        kspec: t.Any,
        kernel_variable: str,
        default_value: t.Any,
    ) -> t.Any:
        """Return a copy of a spec with one parameter replaced."""
        result = copy.deepcopy(kspec)

        result.argv = self.format_kernel_cmd(
            list(result.argv or []),
            {kernel_variable: default_value},
        )

        result.env = self.format_kernel_env(
            dict(getattr(result, "env", None) or {}),
            {kernel_variable: default_value},
        )

        return result


    def check_kernel_custom_all_default_values(self, kspec:KernelSpec):
        assert kernel_spec is not None
        properties = self._parameter_properties(kspec)
        if isinstance(properties, dict):
            has_default = True

            new_kspec = {}
            for property_key, property_value in properties.items():
                if "default" in property_value:
                    new_kspec = self.replace_by_default(
                        kspec, property_key, property_value["default"]
                    )
                else:
                    has_default = False

            if has_default is False:
                result = {"kspec": new_kspec, "all_have_default": False}
            else:
                # check if there is anything after replacing
                total_sum_kernel_variables = self.get_argv_env_kernel_variables(kspec=new_kspec)

                if total_sum_kernel_variables > 0:
                    result = {"kspec": new_kspec, "all_have_default": False}
                else:
                    result = {"kspec": new_kspec, "all_have_default": True}
        else:
            result = {"kspec": kspec, "all_have_default": False}
        return result


    def check_parameterized_kernel(
        self,
        kspec: t.Any,
        allow_insecure_kernelspec_params: bool = False,
    ) -> t.Any | None:
        """Apply the security policy and default-value fallback."""
        is_secure = self.check_kernel_is_secure(kspec)

        result = copy.deepcopy(kspec)
        metadata = dict(getattr(result, "metadata", None) or {})
        metadata["is_secure"] = is_secure
        result.metadata = metadata

        if is_secure or allow_insecure_kernelspec_params:
            return result

        fallback = self.check_kernel_custom_all_default_values(result)
        if fallback["all_have_default"]:
            fallback_spec = fallback["kspec"]
            fallback_metadata = dict(
                getattr(fallback_spec, "metadata", None) or {}
            )
            fallback_metadata["is_secure"] = False
            fallback_spec.metadata = fallback_metadata
            return fallback_spec
        else:
            return None

    def get_custom_kernel_spec_value(self, launch_args, custom_kernel_default_value):
        custom_kernel_dict = {}
        if "custom_kernel_specs" in launch_args:
            custom_kernel_dict = launch_args["custom_kernel_specs"]
            # check is custom kernel variables are full if not then we should take default ones
            if custom_kernel_default_value:
                for key, value in custom_kernel_default_value.items():
                    if isinstance(custom_kernel_dict, dict) and key not in custom_kernel_dict:
                        custom_kernel_dict[key] = value
        elif custom_kernel_default_value:
            # if not but default values are present into a kernel.json file then we have to take them
            custom_kernel_dict = self.custom_kernel_default_value
        return custom_kernel_dict


    def clear_custom_kernel_parameters(self, kernel_parameters: t.Any) -> t.Any:
        """
        Safely removes unresolved custom placeholders from lists or dicts.
        Falls back to original parameters if the filtered result is completely empty.
        """
        if isinstance(kernel_parameters, list):
            clean_parameters = [
                item for item in kernel_parameters
                if not self.has_custom_parameter(item)
            ]
        elif isinstance(kernel_parameters, dict):
            clean_parameters = {
                key: value for key, value in kernel_parameters.items()
                if not self.has_custom_parameter(value)
            }
        else:
            if isinstance(kernel_parameters, str):
                if self.has_custom_parameter(kernel_parameters):
                    return ""
                return kernel_parameters

        if not clean_parameters:
            return kernel_parameters

        return clean_parameters


    def update_custom_env_parameters(self, launch_args, custom_kernel_default_value, env: t.Dict[str, str]) -> t.Dict[str, str]:
        custom_kernel_dict = self.get_custom_kernel_spec_value(launch_args, custom_kernel_default_value)
        newEnv = self.format_kernel_env(env, custom_kernel_dict)
        return self.clear_custom_kernel_parameters(newEnv)










