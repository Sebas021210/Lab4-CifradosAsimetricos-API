from fastapi import APIRouter
from models.cifrados import User
from config.database import collection_name
from bson import ObjectId

router = APIRouter()

# POST - Create a new user
@router.post("/register")
async def create_user(user: User):
    collection_name.insert_one(dict(user))
    return {"message": "User created successfully"}

# DELETE - Delete a user by ID
@router.delete("/delete/{user_id}")
async def delete_user(user_id: str):
    result = collection_name.delete_one({"_id": ObjectId(user_id)})
    if result.deleted_count == 1:
        return {"message": "User deleted successfully"}
    else:
        return {"message": "User not found"}
