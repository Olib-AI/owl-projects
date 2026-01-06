#!/bin/bash
echo "Starting Easy Crawl..."

# Start Backend
echo "Starting Backend on http://localhost:8000"
source venv/bin/activate
uvicorn backend.main:app --reload --port 8000 &
BACKEND_PID=$!

# Start Frontend
echo "Starting Frontend on http://localhost:5173"
cd frontend
npm run dev &
FRONTEND_PID=$!

echo "Easy Crawl is running!"
echo "Backend PID: $BACKEND_PID"
echo "Frontend PID: $FRONTEND_PID"
echo "Press Ctrl+C to stop."

wait
