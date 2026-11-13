# SPDX-FileCopyrightText: 2022 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0

from typing import List, Optional, Set

from actions.spdx.model import Document, Relationship, RelationshipType, SpdxNoAssertion, SpdxNone
from actions.spdx.validation.spdx_id_validators import get_list_of_all_spdx_ids, validate_spdx_id
from actions.spdx.validation.validation_message import SpdxElementType, ValidationContext, ValidationMessage


def validate_relationships(
    relationships: List[Relationship], spdx_version: str, document: Document,
    spdx_ids: Optional[Set[str]] = None,
) -> List[ValidationMessage]:
    if spdx_ids is None:
        spdx_ids = set(get_list_of_all_spdx_ids(document))
    validation_messages = []
    for relationship in relationships:
        validation_messages.extend(validate_relationship(relationship, spdx_version, document, spdx_ids))

    return validation_messages


def validate_relationship(
    relationship: Relationship, spdx_version: str, document: Document,
    spdx_ids: Optional[Set[str]] = None,
) -> List[ValidationMessage]:
    if spdx_ids is None:
        spdx_ids = set(get_list_of_all_spdx_ids(document))
    validation_messages = []
    context = ValidationContext(element_type=SpdxElementType.RELATIONSHIP, full_element=relationship)

    relationship_type: RelationshipType = relationship.relationship_type

    messages: List[str] = validate_spdx_id(
        relationship.spdx_element_id, document, check_document=True, spdx_ids=spdx_ids)
    for message in messages:
        validation_messages.append(ValidationMessage(message, context))

    if relationship.related_spdx_element_id not in [SpdxNone(), SpdxNoAssertion()]:
        messages: List[str] = validate_spdx_id(
            relationship.related_spdx_element_id, document, check_document=True, spdx_ids=spdx_ids)
        for message in messages:
            validation_messages.append(ValidationMessage(message, context))

    if spdx_version == "SPDX-2.2":
        if (
            relationship_type == RelationshipType.SPECIFICATION_FOR
            or relationship_type == RelationshipType.REQUIREMENT_DESCRIPTION_FOR
        ):
            validation_messages.append(ValidationMessage(f"{relationship_type} is not supported in SPDX-2.2", context))

    return validation_messages
