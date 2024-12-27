import requests
import os


API_KEY = os.getenv("API_KEY")
FILE_PATH = os.getenv("FILE_PATH")

URL = "https://www.virustotal.com/api/v3/files"


headers = {
    "accept": "application/json",
    "x-apikey": API_KEY,
}

