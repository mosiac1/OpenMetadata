# generated by datamodel-codegen:
#   filename:  schema/entity/data/database.json
#   timestamp: 2021-12-02T02:38:07+00:00

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field, constr

from ...type import basic, entityHistory, entityReference, usageDetails


class DatabaseName(BaseModel):
    __root__: constr(regex=r'^[^.]*$', min_length=1, max_length=64) = Field(
        ..., description='Name that identifies the database.'
    )


class Database(BaseModel):
    id: Optional[basic.Uuid] = Field(
        None, description='Unique identifier that identifies this database instance.'
    )
    name: DatabaseName = Field(..., description='Name that identifies the database.')
    fullyQualifiedName: Optional[str] = Field(
        None,
        description="Name that uniquely identifies a database in the format 'ServiceName.DatabaseName'.",
    )
    displayName: Optional[str] = Field(
        None, description='Display Name that identifies this database.'
    )
    description: Optional[str] = Field(
        None, description='Description of the database instance.'
    )
    version: Optional[entityHistory.EntityVersion] = Field(
        None, description='Metadata version of the entity.'
    )
    updatedAt: Optional[basic.DateTime] = Field(
        None,
        description='Last update time corresponding to the new version of the entity.',
    )
    updatedBy: Optional[str] = Field(None, description='User who made the update.')
    href: Optional[basic.Href] = Field(
        None, description='Link to the resource corresponding to this entity.'
    )
    owner: Optional[entityReference.EntityReference] = Field(
        None, description='Owner of this database.'
    )
    service: entityReference.EntityReference = Field(
        ...,
        description='Link to the database cluster/service where this database is hosted in.',
    )
    location: Optional[entityReference.EntityReference] = Field(
        None, description='Reference to the Location that contains this database.'
    )
    usageSummary: Optional[usageDetails.TypeUsedToReturnUsageDetailsOfAnEntity] = Field(
        None, description='Latest usage information for this database.'
    )
    tables: Optional[entityReference.EntityReferenceList] = Field(
        None, description='References to tables in the database.'
    )
    changeDescription: Optional[entityHistory.ChangeDescription] = Field(
        None, description='Change that lead to this version of the entity.'
    )
