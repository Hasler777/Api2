import re
from typing import Optional

from pydantic import BaseModel, EmailStr, field_validator



class UserCreate(BaseModel):
    name: str
    email: EmailStr
    age: Optional[int] = None
    is_subscribed: Optional[bool] = None

    @field_validator("age")
    @classmethod
    def validate_age(cls, v):
        if v is not None and v <= 0:
            raise ValueError("Возраст должен быть положительным числом")
        return v



class LoginData(BaseModel):
    username: str
    password: str



class CommonHeaders(BaseModel):
    user_agent: str
    accept_language: str

    @field_validator("accept_language")
    @classmethod
    def validate_accept_language(cls, v):
        pattern = (
            r"^[a-zA-Z]{1,8}(-[a-zA-Z0-9]{1,8})*"
            r"(,\s*[a-zA-Z]{1,8}(-[a-zA-Z0-9]{1,8})*"
            r"(;\s*q=(0(\.\d{0,3})?|1(\.0{0,3})?))?)*$"
        )
        if not re.match(pattern, v):
            raise ValueError("Неверный формат Accept-Language")
        return v
