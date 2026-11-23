from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress


class Alert(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9_-]+$")
    host: str = Field(min_length=1, max_length=120)
    title: str = Field(min_length=1, max_length=500)
    description: str = Field(max_length=4000)
    source_ip: IPvAnyAddress | None = None
    category: Literal["authentication", "execution", "network", "file", "other"] = "other"


class Review(BaseModel):
    approved: bool
    note: str = Field(default="", max_length=1000)
