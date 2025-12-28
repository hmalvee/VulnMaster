# VulnMaster Setup Guide

## Prerequisites

- Python 3.8 or higher
- Node.js 16 or higher and npm

## Backend Setup

1. Navigate to the backend directory:
   ```bash
   cd backend
   ```

2. Create a virtual environment (recommended):
   ```bash
   python -m venv venv
   ```

3. Activate the virtual environment:
   - Windows:
     ```bash
     venv\Scripts\activate
     ```
   - Linux/Mac:
     ```bash
     source venv/bin/activate
     ```

4. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

5. Start the FastAPI server:
   ```bash
   uvicorn app.main:app --reload
   ```

   The API will be available at `http://localhost:8000`
   
   You can also view the interactive API documentation at `http://localhost:8000/docs`

## Frontend Setup

1. Navigate to the frontend directory:
   ```bash
   cd frontend
   ```

2. Install Node.js dependencies:
   ```bash
   npm install
   ```

3. Start the development server:
   ```bash
   npm run dev
   ```

   The frontend will be available at `http://localhost:5173`

## Usage

1. Ensure both backend and frontend servers are running
2. Open your browser to `http://localhost:5173`
3. Enter a target URL (ensure you have authorization to scan it!)
4. Select "SQL Injection" as the scan type
5. Click "Start Scan"
6. View the results in the dashboard

## Important Notes

⚠️ **LEGAL WARNING**: 
- Only scan targets you own or have explicit written permission to test
- Unauthorized scanning is illegal in most jurisdictions
- This tool is for educational purposes only
- Use in controlled lab environments only

## Testing Locally

For testing purposes, you can use intentionally vulnerable applications like:
- DVWA (Damn Vulnerable Web Application)
- WebGoat
- Juice Shop

Always run these in isolated, local environments.

## Troubleshooting

### Backend Issues

- **Port 8000 already in use**: Change the port in `backend/app/main.py` or stop the conflicting service
- **Database errors**: Delete `vulnmaster.db` to reset the database
- **Import errors**: Ensure you've activated the virtual environment and installed all dependencies

### Frontend Issues

- **Port 5173 already in use**: Vite will automatically use the next available port
- **API connection errors**: Ensure the backend is running on port 8000
- **Build errors**: Delete `node_modules` and run `npm install` again

