from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware  # 👈 Agregado
from pymongo.mongo_client import MongoClient
from routes.route import router

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  # Dominio del frontend
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(router)
