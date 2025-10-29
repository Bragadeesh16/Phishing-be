from fastapi import FastAPI
from api import monitor_domain, check_impersonation, check_url, predictions_history
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(monitor_domain.router)
app.include_router(check_impersonation.router)
app.include_router(check_url.router)
app.include_router(predictions_history.router)

@app.get("/")
def home():
    return {"message": "Phishing Detection API is running"}

@app.get("/download")
def download_extension():
    path = "/home/bragadeesh/Desktop/phising/Phishing-be/extension.zip"
    return FileResponse(path = path , filename="extension.zip", media_type="application/zip")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
