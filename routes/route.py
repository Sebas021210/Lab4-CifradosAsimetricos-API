from fastapi import APIRouter, UploadFile, Depends, File
from fastapi.responses import StreamingResponse
from cryptography.hazmat.primitives import serialization
from models.model import User, Login
from config.database import collection_name
from security.cifrados import password_sha256, password_verify, create_jwt_token, get_current_user, generate_key_pair, generate_ecc_key_pair, calculate_hash, sign_rsa, sign_ecc
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
    all_files = collection_name.find_one({}, {"files": 1, "files_hash": 1, "files_firma": 1})
    existing_files = all_files["files"] if all_files else []
    existing_files_hash = all_files["files_hash"] if all_files else []
    existing_files_firma = all_files["files_firma"] if all_files else []

    user_dict = dict(user)
    user_dict["password"] = hashed_password 
    user_dict["files"] = existing_files
    user_dict["files_hash"] = existing_files_hash
    user_dict["files_firma"] = existing_files_firma

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
        
# GET - Get all files
@router.get("/files")
async def get_all_files():
    all_files_data = collection_name.find_one({}, {"files": 1, "_id": 0})

    if not all_files_data or "files" not in all_files_data:
        return {"message": "No files found", "files": []}

    files = all_files_data.get("files", [])

    files_username = []
    for file in files:
        parts = file.split('/', 1)
        user_id, filename_part = parts
        user_data = collection_name.find_one({"_id": ObjectId(user_id)}, {"username": 1})
        
        if user_data and "username" in user_data:
            username = user_data["username"]
            filename = f"{username}/{filename_part}"
            files_username.append({"filename": filename})
        else:
            files_username.append({"filename": file})

    return {
        "files": files_username
    }

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
    collection_name.update_many({}, {"$push": {"files": relative_path, "files_hash": None, "files_firma": None}})
    return {"message": "File uploaded successfully", "file_path": relative_path}

# POST - Upload sign file
@router.post("/upload/{method}")
async def upload_sign_file(
    method: str,
    file: UploadFile = File(...),
    private_key_pem: UploadFile = File(...),
    user_id: str = Depends(get_current_user)
):
    if method not in ["rsa", "ecc"]:
        return {"message": "Invalid method. Use 'rsa' or 'ecc'."}
    
    file_bytes = await file.read()
    file_hash = calculate_hash(file_bytes)

    private_key_bytes = await private_key_pem.read()

    if method == "rsa":
        private_key = serialization.load_pem_private_key(private_key_bytes, password=None)
        signature = sign_rsa(private_key, file_bytes)
    else:
        private_key = serialization.load_pem_private_key(private_key_bytes, password=None)
        signature = sign_ecc(private_key, file_bytes)

    user_folder = os.path.join(FILE_SERVER_PATH, str(user_id))
    os.makedirs(user_folder, exist_ok=True)
    file_path = os.path.join(user_folder, file.filename)
    with open(file_path, "wb") as f:
        f.write(file_bytes)

    relative_path = f"{user_id}/{file.filename}"
    signature_hex = signature.hex()

    collection_name.update_many({}, {
        "$push": {
            "files": relative_path,
            "files_hash": file_hash,
            "files_firma": signature_hex
        }
    })

    return {
        "message": "File and signature uploaded successfully",
        "file_path": relative_path,
        "hash": file_hash,
        "signature": signature_hex,
        "method": method
    }

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
