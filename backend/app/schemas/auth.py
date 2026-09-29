from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import Role


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: str | None = None
    full_name: str | None = None
    role: Role
    is_active: bool
    must_change_password: bool
    last_login_at: datetime | None = None
    created_at: datetime | None = None


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class LoginResponse(BaseModel):
    user: UserOut
    csrf_token: str


class MeResponse(BaseModel):
    user: UserOut
    csrf_token: str


class ChangePasswordRequest(BaseModel):
    # Length/complexity is decided by check_password_policy, not the schema, so
    # that every rejection reaches the client as one readable policy message.
    # max_length still bounds the work scrypt can be asked to do.
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=1, max_length=256)


class UserCreateRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[a-zA-Z0-9._-]+$")
    # Length/complexity is decided by check_password_policy, not the schema, so
    # that every rejection reaches the client as one readable policy message.
    # max_length still bounds the work scrypt can be asked to do.
    password: str = Field(min_length=1, max_length=256)
    full_name: str | None = Field(default=None, max_length=255)
    role: Role


class UserUpdateRequest(BaseModel):
    # All fields optional: only what the request actually carries is applied.
    # full_name may be sent as an explicit null to clear it.
    full_name: str | None = Field(default=None, max_length=255)
    role: Role | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=1, max_length=256)
