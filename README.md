# 0Bullshit Backend v2.0

A powerful AI-powered backend platform for startups, featuring 60 specialized bots, intelligent memory system, and automatic document generation.

## Features

- 🤖 60 Specialized AI Bots
- 🧠 Intelligent Neural Memory System
- 📝 Automatic Document Generation
- 🌍 Multi-language Support
- 🔒 JWT Authentication
- 📊 Supabase Database Integration

## Tech Stack

- Backend: Flask + Python
- Database: Supabase (PostgreSQL)
- AI: Gemini 2.0 Flash
- Deployment: Render
- Authentication: JWT

## Setup

1. Clone the repository
```bash
git clone https://github.com/yourusername/0bullshit-backend-v2.git
cd 0bullshit-backend-v2
```

2. Create and activate virtual environment
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies
```bash
pip install -r requirements.txt
```

4. Set up environment variables
```bash
cp .env.example .env
# Edit .env with your credentials
```

5. Initialize database
```bash
python database/setup_script.py
```

6. Run the application
```bash
python app.py
```

## API Endpoints

### Authentication
- POST /auth/register - User registration
- POST /auth/login - User login

### Chat & Bots
- POST /chat/bot - Main chat endpoint with intelligent routing
- GET /bots/available - List available bots

### Memory System
- GET /user/memory-dashboard - Complete memory dashboard
- GET /project/next-steps - Recommended next steps

### Documents
- GET /documents - User documents
- GET /documents/{id}/view - View document
- GET /documents/{id}/download - Download document (MD/HTML/PDF)

## Deployment

The application is configured for deployment on Render. Simply connect your GitHub repository and set the following environment variables:

- GEMINI_API_KEY
- DATABASE_URL
- JWT_SECRET
- PORT

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details. 