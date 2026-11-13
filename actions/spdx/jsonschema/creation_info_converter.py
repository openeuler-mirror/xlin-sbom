# SPDX-FileCopyrightText: 2022 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
from typing import Any, Type

from actions.spdx.datetime_conversions import datetime_to_iso_string
from actions.spdx.jsonschema.converter import TypedConverter
from actions.spdx.jsonschema.creation_info_properties import CreationInfoProperty
from actions.spdx.jsonschema.json_property import JsonProperty
from actions.spdx.jsonschema.optional_utils import apply_if_present
from actions.spdx.model import CreationInfo, Document


class CreationInfoConverter(TypedConverter[CreationInfo]):
    def get_data_model_type(self) -> Type[CreationInfo]:
        return CreationInfo

    def get_json_type(self) -> Type[JsonProperty]:
        return CreationInfoProperty

    def _get_property_value(
        self,
        creation_info: CreationInfo,
        creation_info_property: CreationInfoProperty,
        _document: Document | None = None,
    ) -> Any:
        if creation_info_property == CreationInfoProperty.CREATED:
            return datetime_to_iso_string(creation_info.created)
        elif creation_info_property == CreationInfoProperty.CREATORS:
            return [creator.to_serialized_string() for creator in creation_info.creators] or None
        elif creation_info_property == CreationInfoProperty.LICENSE_LIST_VERSION:
            return apply_if_present(str, creation_info.license_list_version)
        elif creation_info_property == CreationInfoProperty.COMMENT:
            return creation_info.creator_comment
