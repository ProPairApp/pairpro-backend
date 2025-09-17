from fastapi import APIRouter, Depends, HTTPException
import os, time, hashlib
from .auth import get_current_user  # this makes sure the user is logged in

router = APIRouter(prefix="/uploads", tags=["uploads"])

@router.post("/sign")
def sign_upload(current_user=Depends(get_current_user)):
    """
    Creates a Cloudinary signature so the client can upload files directly.
    """
    cloud_name = os.getenv("CLOUDINARY_CLOUD_NAME")
    api_key = os.getenv("CLOUDINARY_API_KEY")
    api_secret = os.getenv("CLOUDINARY_API_SECRET")
    if not (cloud_name and api_key and api_secret):
        raise HTTPException(500, "Cloudinary not configured")

    # timestamp = required by Cloudinary
    ts = int(time.time())

    # text that Cloudinary expects us to sign
    to_sign = f"timestamp={ts}{api_secret}"

    # hash it into a signature
    sig = hashlib.sha1(to_sign.encode("utf-8")).hexdigest()

    # return data your frontend expects
    return {
        "cloud_name": cloud_name,
        "api_key": api_key,
        "timestamp": ts,
        "signature": sig,
    }
