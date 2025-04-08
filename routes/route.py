from fastapi import APIRouter, UploadFile, Depends, File
from fastapi.responses import StreamingResponse
from models.model import User, Login
from config.database import collection_name
from security.cifrados import password_sha256, password_verify, create_jwt_token, get_current_user, generate_key_pair, generate_ecc_key_pair
from bson import ObjectId
import os
import zipfile
import io

router = APIRouter()

# Path Fileserver
FILE_SERVER_PATH = "fileserver"

# POST - Create a new user
@router.post("/register")
async def create_user(user: User):
    hashed_password = password_sha256(user.password)
    all_files = collection_name.find_one({}, {"files": 1})
    existing_files = all_files["files"] if all_files else []

    user_dict = dict(user)
    user_dict["password"] = hashed_password 
    user_dict["files"] = existing_files

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

# POST - Keys generation
@router.post("/keys")
async def generate_keys(user_id: str = Depends(get_current_user)):
    user = collection_name.find_one({"_id": ObjectId(user_id)})
    if not user:
        return {"message": "User not found"}

    rsa_private_key, rsa_public_key = generate_key_pair()
    ecc_private_key, ecc_public_key = generate_ecc_key_pair()

    os.makedirs("private_keys", exist_ok=True)
    with open(f"private_keys/{user_id}_rsa_private.pem", "w") as f:
        f.write(rsa_private_key)
    with open(f"private_keys/{user_id}_ecc_private.pem", "w") as f:
        f.write(ecc_private_key)

    collection_name.update_one({"_id": ObjectId(user_id)}, {"$set": {
        "rsa_public_key": rsa_public_key,
        "ecc_public_key": ecc_public_key
    }})

    return {
        "message": "Keys generated successfully",
        "rsa_public_key": rsa_public_key,
        "ecc_public_key": ecc_public_key,
    }

# GET - Download file
@router.get("/download-private-keys")
async def download_private_keys(user_id: str = Depends(get_current_user)):
    rsa_path = f"private_keys/{user_id}_rsa_private.pem"
    ecc_path = f"private_keys/{user_id}_ecc_private.pem"

    if not os.path.exists(rsa_path) or not os.path.exists(ecc_path):
        return {"message": "Private keys not found"}
    
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zipf:
        zipf.write(rsa_path, arcname=f"{user_id}_rsa_private.pem")
        zipf.write(ecc_path, arcname=f"{user_id}_ecc_private.pem")

    zip_buffer.seek(0)

    return StreamingResponse(
    zip_buffer,
    media_type="application/zip",
    headers={"Content-Disposition": "attachment; filename=private_keys.zip"}
    )

# POST - Upload file
@router.post("/upload")
async def upload_file(file: UploadFile = File(...), user_id: str = Depends(get_current_user)):
    user_folder = os.path.join(FILE_SERVER_PATH, str(user_id))
    os.makedirs(user_folder, exist_ok=True)

    file_path = os.path.join(user_folder, file.filename)

    with open(file_path, "wb") as f:
        f.write(await file.read())

    relative_path = f"{user_id}/{file.filename}"
    collection_name.update_many({}, {"$push": {"files": relative_path}})
    return {"message": "File uploaded successfully", "file_path": relative_path}

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
