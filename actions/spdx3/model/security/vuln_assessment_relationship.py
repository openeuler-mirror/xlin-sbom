# SPDX-FileCopyrightText: 2023 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
from abc import abstractmethod
from datetime import datetime

from typing import Optional

from actions.common.typing.dataclass_with_properties import dataclass_with_properties
from actions.spdx3.model import Relationship


@dataclass_with_properties
class VulnAssessmentRelationship(Relationship):
    assessed_element: Optional[str] = None  # id of the element
    published_time: Optional[datetime] = None
    supplied_by: Optional[str] = None
    modified_time: Optional[datetime] = None
    withdrawn_time: Optional[datetime] = None

    @abstractmethod
    def __init__(self):
        pass
