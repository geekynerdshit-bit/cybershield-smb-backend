from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from routes.scan import router as scan_router

load_dotenv()  # Must be before any agent imports that read env vars



app = FastAPI(
    title="CyberShield SMB API",
    description="Agentic AI cybersecurity scanner for small businesses",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",    # Vite dev server
        "http://localhost:3000",
        "https://*.vercel.app",     # All Vercel preview + production deploys
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan_router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)