from pymongo import MongoClient

client = MongoClient("mongodb+srv://ssolorzano10:Sebas101202@cluster0.chjg94q.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
db = client.Lab04_Cifrados
collection_name = db["Cifrados"]
