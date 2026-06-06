"""
files.py — File Upload and Download Module
============================================
Vulnerabilities:
  A01 - Path Traversal: ../../etc/passwd style attacks
  A03 - Unrestricted file upload (no type/size validation)
  A05 - Upload directory publicly accessible
"""

import os
import shutil
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from fastapi.responses import FileResponse
from pathlib import Path

from auth import get_current_user

router = APIRouter()

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)


# ============================================================
# VULNERABILITY: A01 - Path Traversal
# filename parameter is not sanitized — attacker can read
# arbitrary files on the server filesystem
#
# Attack examples:
#   GET /files/download?filename=../../etc/passwd
#   GET /files/download?filename=../../app/auth.py  (leaks source)
#   GET /files/download?filename=../../.env
# ============================================================
@router.get("/download")
async def download_file(filename: str, current_user: dict = Depends(get_current_user)):
    # INSECURE: joins user-controlled filename directly to base path
    # Real fix:
    #   safe_path = Path(UPLOAD_DIR).resolve() / Path(filename).name
    #   if not str(safe_path).startswith(str(Path(UPLOAD_DIR).resolve())):
    #       raise HTTPException(400, "Invalid path")
    file_path = os.path.join(UPLOAD_DIR, filename)

    if not os.path.exists(file_path):
        raise HTTPException(
            status_code=404,
            detail=f"File not found: {file_path}"  # INSECURE: exposes full path
        )

    return FileResponse(file_path)


# ============================================================
# VULNERABILITY: A03 - Unrestricted File Upload
# No validation of file type, content, or size
# Attacker can upload .py, .sh, .php files and potentially
# execute them if the server serves them
#
# Attack: upload a Python webshell → execute arbitrary commands
# ============================================================
@router.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user),
):
    # INSECURE: no file type validation
    # INSECURE: no file size limit
    # INSECURE: original filename used directly (path traversal risk)
    # INSECURE: no malware scanning
    # Real fix: validate extension allowlist, scan content, generate random name

    filename = file.filename  # attacker-controlled filename

    # VULNERABILITY: filename not sanitized — could contain ../
    save_path = os.path.join(UPLOAD_DIR, filename)

    with open(save_path, "wb") as f:
        shutil.copyfileobj(file.file, f)

    return {
        "message": "File uploaded",
        "path": save_path,          # INSECURE: returns server path
        "filename": filename,
        "size": os.path.getsize(save_path),
    }


# ============================================================
# VULNERABILITY: A01 - Directory listing enabled
# Returns all files in the uploads directory, including
# files uploaded by other users
# ============================================================
@router.get("/list")
async def list_files(current_user: dict = Depends(get_current_user)):
    # INSECURE: no filtering by owner — all users see all uploads
    try:
        files = []
        for f in os.listdir(UPLOAD_DIR):
            full_path = os.path.join(UPLOAD_DIR, f)
            files.append({
                "name": f,
                "size": os.path.getsize(full_path),
                "path": full_path,   # INSECURE: server path exposed
            })
        return {"files": files, "upload_dir": os.path.abspath(UPLOAD_DIR)}
    except Exception as e:
        return {"error": str(e), "upload_dir": UPLOAD_DIR}


# ============================================================
# VULNERABILITY: A01 - Any user can delete any file by name
# No ownership tracking, no authorization check
# ============================================================
@router.delete("/delete")
async def delete_file(filename: str, current_user: dict = Depends(get_current_user)):
    # INSECURE: path traversal + no ownership check
    file_path = os.path.join(UPLOAD_DIR, filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        return {"message": f"Deleted {filename}"}
    raise HTTPException(status_code=404, detail="File not found")
