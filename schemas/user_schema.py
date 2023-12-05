from typing import Optional
from pydantic import *
import uuid

class UserSchema(BaseModel):
    Name:str
    Status:Optional[str] = "Negatif"
    Tagid:Optional[str] = None
    Phone:Optional[int] = None
    Email:str
    NIK:Optional[int] = None
    Password:str
    UserID:Optional[str] = uuid.uuid4().hex
    Photo:Optional[str] = "Default.png"