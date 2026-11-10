
from pydantic import BaseModel, Field


class UserRegister(BaseModel):
    username: str = Field(min_length=3, max_length=100)
    email: str = Field(min_length=5, max_length=150)
    password: str = Field(min_length=8, max_length=128)


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    role: str

    model_config = {"from_attributes": True}


class TokenResponse(BaseModel):
    access_token: str
    token_type: str




class PrivateDataCreate(BaseModel):
    sensitive_data: str = Field(min_length=1, max_length=5000)


class PrivateDataResponse(BaseModel):
    id: int
    message: str
