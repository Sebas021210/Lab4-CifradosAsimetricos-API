from fastapi import APIRouter, Depends
from models.model import User, Login
from config.database import collection_name
from security.cifrados import password_sha256, password_verify, create_jwt_token, get_current_user
from bson import ObjectId

router = APIRouter()

# POST - Create a new user
@router.post("/register")
async def create_user(user: User):
    hashed_password = password_sha256(user.password)
    user_dict = dict(user)
    user_dict["password"] = hashed_password

    collection_name.insert_one(user_dict)
    return {"message": "User created successfully"}

# POST - Login user
@router.post("/login")
async def login_user(login: Login):
    user = collection_name.find_one({"email": login.email})
    if user and password_verify(login.password, user["password"]):
        token = create_jwt_token(str(user["_id"]))
        return {"message": "Login successful", "token": token}
    else:
        if user is None:
            return {"message": "User not found"}
        else:
            return {"message": "Invalid password"}

# GET - Get token information
@router.get("/protected")
async def protected_route(user_id: str = Depends(get_current_user)):
    return {"message": "You have access!", "user_id": user_id}

# DELETE - Delete a user by ID
@router.delete("/delete/{user_id}")
async def delete_user(user_id: str):
    result = collection_name.delete_one({"_id": ObjectId(user_id)})
    if result.deleted_count == 1:
        return {"message": "User deleted successfully"}
    else:
        return {"message": "User not found"}
