"""
FastAPI application entry point for VulnMaster.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .database import init_db
from .routers import scans, websocket

# Initialize FastAPI app
app = FastAPI(
    title="VulnMaster API",
    description="Educational vulnerability scanner API",
    version="2.0.0"
)

# Configure CORS to allow frontend requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],  # React dev servers
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize database (run on startup)
@app.on_event("startup")
async def startup_event():
    await init_db()

# Include routers
app.include_router(scans.router)
app.include_router(websocket.router)


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": "VulnMaster API",
        "description": "Educational vulnerability scanner",
        "version": "2.0.0"
    }


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

