"""
Database Schemas for Store Rating App

Each Pydantic model represents a MongoDB collection.
Collection name is lowercase of the class name.
- User -> "user"
- Store -> "store"
- Review -> "review"
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional
from datetime import datetime

class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Unique email address")
    password_hash: str = Field(..., description="Hashed password")
    role: str = Field("user", description="Role: user, owner, admin")
    is_active: bool = Field(True, description="Whether user is active")

class Store(BaseModel):
    name: str = Field(..., description="Store name")
    description: Optional[str] = Field(None, description="Store description")
    address: Optional[str] = Field(None, description="Address")
    owner_id: str = Field(..., description="Owner user _id (string)")
    average_rating: float = Field(0.0, ge=0, le=5, description="Average rating")
    review_count: int = Field(0, ge=0, description="Number of reviews")

class Review(BaseModel):
    store_id: str = Field(..., description="Store _id (string)")
    user_id: str = Field(..., description="User _id (string)")
    rating: int = Field(..., ge=1, le=5, description="Rating 1-5")
    comment: Optional[str] = Field(None, description="Optional review text")
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
