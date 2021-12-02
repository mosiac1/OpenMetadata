# generated by datamodel-codegen:
#   filename:  data/tags/personalDataTags.json
#   timestamp: 2021-12-02T02:38:07+00:00

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Extra, Field


class Model(BaseModel):
    class Config:
        extra = Extra.forbid

    __root__: Any = Field(
        ...,
        description='Tags related classifying **Personal data** as defined by **GDPR.**<br/><br/>_Note to Legal - This tag category is provided as a starting point. Please review and update the tags based on your company policy. Also, add a reference to your GDPR policy document in this description._',
    )
