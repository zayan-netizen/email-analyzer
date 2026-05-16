from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware

from backend.parser import parse_email
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
	return {
		"message": "Email analyzer backend running"
	}

@app.post("/analyze")
async def analyse_email(file: UploadFile = File(...)):

	content = await file.read()

	parsed_email = parse_email(content)

	return parsed_email