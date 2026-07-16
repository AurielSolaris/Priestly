from pydantic import BaseModel
from datetime import datetime

class Handshake(BaseModel):
    id: int
    user_id: int
    device_id: int
    timestamp: datetime
    status: str

class Message(BaseModel):
    id: int
    sender_id: int
    receiver_id: int
    ciphertext: str
    timestamp: datetime
    status: str

