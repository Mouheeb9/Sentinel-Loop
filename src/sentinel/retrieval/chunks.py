"""The unit stored in the retrieval index — shared by the ATT&CK and Sigma loaders."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class Chunk(BaseModel):
    """One retrievable document: a single ATT&CK technique or a single Sigma rule."""

    id: str  # "T1059.001" for techniques, the rule's UUID for Sigma
    kind: Literal["technique", "sigma_rule"]
    title: str
    text: str  # what gets embedded and shown to the model
    platforms: list[str] = Field(default_factory=list)  # lowercased, e.g. "windows"
    logsource: str | None = None  # "category/product/service" for Sigma rules
    technique_ids: list[str] = Field(default_factory=list)  # ATT&CK IDs this chunk maps to
