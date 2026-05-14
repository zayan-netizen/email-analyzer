from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
	CORSMiddleware,
	allow_origins=["*"],
	allow_credentials=True,
	allow_methods=["*"],
	allow_headers=["*"],
)

@app.get("/")
def home():
	return {"message": "Email analyzer backend running"}

@app.post("/analyze")
async def analyse_email(file: UploadFile = File(...)):

	content = await file.read()

	return {
		"filename": file.filename,
		"size_in_bytes": len(content),
		"message": "File recieved successfully"
	}