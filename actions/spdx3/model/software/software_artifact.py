# SPDX-FileCopyrightText: 2023 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
from abc import abstractmethod
from dataclasses import field

from typing import List, Optional

from actions.common.typing.dataclass_with_properties import dataclass_with_properties
from actions.spdx3.model import Artifact
from actions.spdx3.model.licensing import LicenseField
from actions.spdx3.model.software import SoftwarePurpose


@dataclass_with_properties
class SoftwareArtifact(Artifact):
    content_identifier: Optional[str] = None
    primary_purpose: Optional[SoftwarePurpose] = None
    additional_purpose: List[SoftwarePurpose] = field(default_factory=list)
    concluded_license: Optional[LicenseField] = None
    declared_license: Optional[LicenseField] = None
    copyright_text: Optional[str] = None
    attribution_text: Optional[str] = None

    @abstractmethod
    def __init__(self):
        pass
