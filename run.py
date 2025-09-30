"""
Simple runner for the AI Bug Bounty Scanner backend
"""
import uvicorn

if __name__ == "__main__":
    print("=" * 60)
    print("AI Bug Bounty Scanner - Starting")
    print("=" * 60)
    print("Backend API: http://127.0.0.1:8000")
    print("API Docs: http://127.0.0.1:8000/docs")
    print("=" * 60)
    print("\nPress CTRL+C to stop\n")
    
    uvicorn.run(
        "backend.main:app",
        host="127.0.0.1",
        port=8000,
        reload=False,  # Disable reload for stability on Windows
        log_level="info"
    )

