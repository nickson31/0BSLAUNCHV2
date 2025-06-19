# -*- coding: utf-8 -*-
"""
0Bullshit Backend v2.0 - Sistema Gamificado con 60 Bots
Sistema de créditos, suscripciones y memoria neuronal
"""

# ==============================================================================
#           IMPORTS
# ==============================================================================

print("1. Loading libraries...")
from flask import Flask, request, jsonify, session, redirect, url_for
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import pandas as pd
import google.generativeai as genai
import json
import ast
import re
import warnings
import time
import os
import sqlalchemy
from datetime import datetime, timedelta
import uuid
from sqlalchemy import text
import secrets
import jwt
from functools import wraps
import hashlib
import bcrypt
import requests

# Google Auth
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

# ==============================================================================
#           CONFIGURATION
# ==============================================================================

print("2. Configuring application...")
app = Flask(__name__)

# Rate Limiter Configuration
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# CORS Configuration
CORS(app, 
     supports_credentials=True,
     origins=[
         'https://v0-0-bull-shit.vercel.app',
         'http://localhost:3000',
         'http://localhost:3001'
     ],
     methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
     allow_headers=['Content-Type', 'Authorization'])

app.secret_key = os.environ.get('JWT_SECRET', secrets.token_hex(16))
warnings.filterwarnings('ignore')

# Environment Variables
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
DATABASE_URL = os.environ.get("DATABASE_URL")
JWT_SECRET = os.environ.get("JWT_SECRET", secrets.token_hex(32))
UNIPILE_API_KEY = os.environ.get("UNIPILE_API_KEY")  # Para Pro plan
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
FRONTEND_URL = os.environ.get("FRONTEND_URL", "https://v0-0-bull-shit.vercel.app")

# Debug info para Google Auth
print(f"🔐 GOOGLE_CLIENT_ID configured: {'✅' if GOOGLE_CLIENT_ID else '❌'}")
print(f"🗄️ DATABASE_URL configured: {'✅' if DATABASE_URL else '❌'}")
print(f"🔑 JWT_SECRET configured: {'✅' if JWT_SECRET else '❌'}")

# Verificar configuración crítica
if not GEMINI_API_KEY:
    print("❌ FATAL: GEMINI_API_KEY not found.")
if not DATABASE_URL:
    print("❌ FATAL: DATABASE_URL not found.")
if not GOOGLE_CLIENT_ID:
    print("⚠️ WARNING: GOOGLE_CLIENT_ID not found - Google Auth will not work")

# Configure AI APIs
try:
    genai.configure(api_key=GEMINI_API_KEY)
    MODEL_NAME = "gemini-2.0-flash"
    print("✅ Gemini API configured.")
except Exception as e:
    print(f"❌ ERROR configuring Gemini: {e}")

# Connect to Database
try:
    engine = sqlalchemy.create_engine(DATABASE_URL)
    print("✅ Database connection established.")
except Exception as e:
    print(f"❌ ERROR connecting to database: {e}")
    engine = None

# ==============================================================================
#           SECURITY FUNCTIONS
# ==============================================================================

def validate_password(password):
    """Valida que la contraseña cumpla con los requisitos"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    
    return True, "Password is valid"

def generate_refresh_token(user_id):
    """Genera refresh token para el usuario"""
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(days=30),
        'iat': datetime.utcnow(),
        'type': 'refresh'
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def store_refresh_token(user_id, token):
    """Almacena refresh token en la base de datos"""
    try:
        with engine.connect() as conn:
            conn.execute(
                text("""
                    INSERT INTO refresh_tokens (
                        user_id, token, expires_at
                    ) VALUES (
                        :user_id, :token, NOW() + INTERVAL '30 days'
                    )
                """),
                {
                    "user_id": user_id,
                    "token": token
                }
            )
            conn.commit()
            return True
    except Exception as e:
        print(f"Error storing refresh token: {e}")
        return False

def verify_refresh_token(token):
    """Verifica refresh token"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        if payload.get('type') != 'refresh':
            return None
            
        with engine.connect() as conn:
            result = conn.execute(
                text("""
                    SELECT * FROM refresh_tokens 
                    WHERE token = :token 
                    AND expires_at > NOW()
                    AND revoked = false
                """),
                {"token": token}
            ).fetchone()
            
            if result:
                return payload['user_id']
            return None
    except Exception as e:
        print(f"Error verifying refresh token: {e}")
        return None

def revoke_refresh_token(token):
    """Revoca refresh token"""
    try:
        with engine.connect() as conn:
            conn.execute(
                text("""
                    UPDATE refresh_tokens 
                    SET revoked = true 
                    WHERE token = :token
                """),
                {"token": token}
            )
            conn.commit()
            return True
    except Exception as e:
        print(f"Error revoking refresh token: {e}")
        return False

# Security Headers Middleware
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# ==============================================================================
#           CONSTANTS AND CONFIGURATIONS
# ==============================================================================

# Credit costs por acción
CREDIT_COSTS = {
    # Bots básicos (todos los planes)
    "basic_bot": 5,
    "advanced_bot": 15,
    "expert_bot": 25,
    "document_generation": 50,
    
    # Growth plan only
    "investor_search_result": 10,
    "employee_search_result": 8,
    
    # Pro plan only
    "template_generation": 20,
    "unipile_message": 5,
    "automated_sequence": 50,
    
    # Premium features
    "market_analysis": 100,
    "business_model": 150,
    "pitch_deck": 200
}

# Planes de suscripción
SUBSCRIPTION_PLANS = {
    "free": {
        "name": "Free",
        "credits_monthly": 100,
        "launch_credits": 100,
        "features": {
            "bots_access": True,
            "investor_search": False,
            "employee_search": False,
            "outreach_templates": False,
            "unlimited_docs": False,
            "neural_memory": False
        }
    },
    "growth": {
        "name": "Growth",
        "credits_monthly": 10000,
        "launch_credits": 100000,
        "features": {
            "bots_access": True,
            "investor_search": True,
            "employee_search": True,
            "outreach_templates": False,
            "unlimited_docs": True,
            "neural_memory": True
        }
    },
    "pro": {
        "name": "Pro Outreach",
        "credits_monthly": 50000,
        "launch_credits": 1000000,
        "features": {
            "bots_access": True,
            "investor_search": True,
            "employee_search": True,
            "outreach_templates": True,
            "unlimited_docs": True,
            "neural_memory": True,
            "unipile_integration": True
        }
    }
}

# ==============================================================================
#           AUTHENTICATION & USER MANAGEMENT
# ==============================================================================

def hash_password(password):
    """Hash password usando bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password, hashed):
    """Verifica password contra hash"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def generate_jwt_token(user_id):
    """Genera JWT token para el usuario"""
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(days=7),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def verify_jwt_token(token):
    """Verifica y decodifica JWT token"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return payload['user_id']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def require_auth(f):
    """Decorator para endpoints que requieren autenticación"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'No authorization token provided'}), 401
        
        if token.startswith('Bearer '):
            token = token[7:]
        
        user_id = verify_jwt_token(token)
        if not user_id:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        # Obtener usuario de la base de datos
        user = get_user_by_id(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return f(user, *args, **kwargs)
    return decorated_function

def require_plan(required_plan):
    """Decorator para endpoints que requieren un plan específico"""
    def decorator(f):
        @wraps(f)
        def decorated_function(user, *args, **kwargs):
            if user['subscription_plan'] != required_plan:
                return jsonify({
                    'error': f'This feature requires a {required_plan} plan',
                    'current_plan': user['subscription_plan']
                }), 403
            return f(user, *args, **kwargs)
        return decorated_function
    return decorator

def get_user_by_id(user_id):
    """Obtiene usuario por ID"""
    try:
        with engine.connect() as conn:
            result = conn.execute(
                text("SELECT * FROM users WHERE id = :user_id"),
                {"user_id": user_id}
            ).fetchone()
            
            if result:
                return {
                    'id': str(result[0]),
                    'email': result[1],
                    'password_hash': result[2] if len(result) > 2 else None,
                    'first_name': result[3],
                    'last_name': result[4],
                    'subscription_plan': result[5],
                    'credits': result[6],
                    'auth_provider': result[7] if len(result) > 7 else 'manual',
                    'google_id': result[8] if len(result) > 8 else None,
                    'created_at': result[9] if len(result) > 9 else None
                }
            return None
    except Exception as e:
        print(f"Error getting user by ID: {e}")
        return None

def get_user_by_email(email):
    """Obtiene usuario por email"""
    try:
        with engine.connect() as conn:
            result = conn.execute(
                text("SELECT * FROM users WHERE email = :email"),
                {"email": email}
            ).fetchone()
            
            if result:
                return {
                    'id': str(result[0]),
                    'email': result[1],
                    'password_hash': result[2] if len(result) > 2 else None,
                    'first_name': result[3],
                    'last_name': result[4],
                    'subscription_plan': result[5],
                    'credits': result[6],
                    'auth_provider': result[7] if len(result) > 7 else 'manual',
                    'google_id': result[8] if len(result) > 8 else None,
                    'created_at': result[9] if len(result) > 9 else None
                }
            return None
    except Exception as e:
        print(f"Error getting user by email: {e}")
        return None

def get_user_by_google_id(google_id):
    """Obtiene usuario por Google ID"""
    try:
        with engine.connect() as conn:
            result = conn.execute(
                text("SELECT * FROM users WHERE google_id = :google_id"),
                {"google_id": google_id}
            ).fetchone()
            
            if result:
                return {
                    'id': str(result[0]),
                    'email': result[1],
                    'password_hash': result[2] if len(result) > 2 else None,
                    'first_name': result[3],
                    'last_name': result[4],
                    'subscription_plan': result[5],
                    'credits': result[6],
                    'auth_provider': result[7] if len(result) > 7 else 'manual',
                    'google_id': result[8] if len(result) > 8 else None,
                    'created_at': result[9] if len(result) > 9 else None
                }
            return None
    except Exception as e:
        print(f"Error getting user by Google ID: {e}")
        return None

def create_user(email, password=None, first_name="", last_name="", auth_provider="manual", google_id=None):
    """Crea nuevo usuario"""
    try:
        user_id = str(uuid.uuid4())
        password_hash = hash_password(password) if password else None
        
        with engine.connect() as conn:
            conn.execute(
                text("""
                    INSERT INTO users (
                        id, email, password_hash, first_name, last_name,
                        subscription_plan, credits, auth_provider, google_id, created_at
                    ) VALUES (
                        :id, :email, :password_hash, :first_name, :last_name,
                        'free', :credits, :auth_provider, :google_id, NOW()
                    )
                """),
                {
                    "id": user_id,
                    "email": email,
                    "password_hash": password_hash,
                    "first_name": first_name,
                    "last_name": last_name,
                    "credits": SUBSCRIPTION_PLANS['free']['launch_credits'],
                    "auth_provider": auth_provider,
                    "google_id": google_id
                }
            )
            conn.commit()
            return user_id
    except Exception as e:
        print(f"Error creating user: {e}")
        return None

def get_user_credits(user_id):
    """Obtiene créditos del usuario"""
    try:
        with engine.connect() as conn:
            result = conn.execute(
                text("SELECT credits FROM users WHERE id = :user_id"),
                {"user_id": user_id}
            ).fetchone()
            return result[0] if result else 0
    except Exception as e:
        print(f"Error getting credits: {e}")
        return 0

def charge_credits(user_id, amount):
    """Cobra créditos al usuario"""
    try:
        with engine.connect() as conn:
            result = conn.execute(
                text("""
                    UPDATE users 
                    SET credits = credits - :amount 
                    WHERE id = :user_id AND credits >= :amount
                    RETURNING credits
                """),
                {"user_id": user_id, "amount": amount}
            ).fetchone()
            
            if result:
                conn.commit()
                return result[0]
            return None
    except Exception as e:
        print(f"Error charging credits: {e}")
        return None

def add_credits(user_id, amount, reason='purchase'):
    """Agrega créditos al usuario"""
    try:
        with engine.connect() as conn:
            result = conn.execute(
                text("""
                    UPDATE users 
                    SET credits = credits + :amount 
                    WHERE id = :user_id
                    RETURNING credits
                """),
                {"user_id": user_id, "amount": amount}
            ).fetchone()
            
            if result:
                log_credit_transaction(user_id, amount, 'credit', reason)
                conn.commit()
                return result[0]
            return None
    except Exception as e:
        print(f"Error adding credits: {e}")
        return None

def log_credit_transaction(user_id, amount, transaction_type, description):
    """Registra transacción de créditos"""
    try:
        with engine.connect() as conn:
            conn.execute(
                text("""
                    INSERT INTO credit_transactions (
                        user_id, amount, type, description, created_at
                    ) VALUES (
                        :user_id, :amount, :type, :description, NOW()
                    )
                """),
                {
                    "user_id": user_id,
                    "amount": amount,
                    "type": transaction_type,
                    "description": description
                }
            )
            conn.commit()
    except Exception as e:
        print(f"Error logging transaction: {e}")

def has_sufficient_credits(user_id, required_amount):
    """Verifica si el usuario tiene suficientes créditos"""
    try:
        current_credits = get_user_credits(user_id)
        return current_credits >= required_amount
    except Exception as e:
        print(f"Error checking credits: {e}")
        return False

def update_subscription_plan(user_id, new_plan):
    """Actualiza el plan de suscripción del usuario"""
    try:
        if new_plan not in SUBSCRIPTION_PLANS:
            return False
            
        with engine.connect() as conn:
            # Update user's subscription plan
            conn.execute(
                text("""
                    UPDATE users 
                    SET subscription_plan = :plan,
                        credits = credits + :additional_credits
                    WHERE id = :user_id
                """),
                {
                    "user_id": user_id,
                    "plan": new_plan,
                    "additional_credits": SUBSCRIPTION_PLANS[new_plan]['launch_credits']
                }
            )
            
            # Create subscription record
            conn.execute(
                text("""
                    INSERT INTO subscriptions (id, user_id, plan, status)
                    VALUES (:id, :user_id, :plan, 'active')
                """),
                {
                    "id": str(uuid.uuid4()),
                    "user_id": user_id,
                    "plan": new_plan
                }
            )
            
            conn.commit()
            return True
    except Exception as e:
        print(f"Error updating subscription: {e}")
        return False

# ==============================================================================
#           BOT SYSTEM
# ==============================================================================

class BotManager:
    def __init__(self):
        self.router = GeminiRouter()
    
    def process_user_request(self, user_input, user_context, user_id):
        """Procesa request del usuario y selecciona el mejor bot"""
        try:
            # Seleccionar bot óptimo
            selected_bot = self.router.select_optimal_bot(user_input, user_context)
            
            # Verificar créditos necesarios
            required_credits = CREDIT_COSTS.get(selected_bot, 5)
            current_credits = get_user_credits(user_id)
            
            if current_credits < required_credits:
                return {
                    'error': 'Insufficient credits',
                    'required': required_credits,
                    'available': current_credits
                }
            
            # Cargar prompt del bot
            with open(f'bots/{selected_bot}.txt', 'r') as f:
                bot_prompt = f.read()
            
            # Generar respuesta
            response = genai.generate_content(
                model=MODEL_NAME,
                contents=[bot_prompt, user_input]
            )
            
            # Cobrar créditos
            charge_credits(user_id, required_credits)
            
            # Guardar en memoria neuronal
            save_neural_interaction(user_id, {
                'bot': selected_bot,
                'input': user_input,
                'response': response.text,
                'credits_used': required_credits
            })
            
            return {
                'bot': selected_bot,
                'response': response.text,
                'credits_used': required_credits
            }
            
        except Exception as e:
            print(f"Error processing request: {e}")
            return {'error': str(e)}

class GeminiRouter:
    def select_optimal_bot(self, user_input, user_context):
        """Selecciona el bot más apropiado usando Gemini"""
        try:
            prompt = f"""
            Based on the following user input and context, select the most appropriate bot from our system.
            
            User Input: {user_input}
            Context: {user_context}
            
            Available bots:
            {list(CREDIT_COSTS.keys())}
            
            Return only the bot name that would be most appropriate.
            """
            
            response = genai.generate_content(
                model=MODEL_NAME,
                contents=[prompt]
            )
            
            selected_bot = response.text.strip()
            if selected_bot in CREDIT_COSTS:
                return selected_bot
            return "basic_bot"  # Default bot
            
        except Exception as e:
            print(f"Error selecting bot: {e}")
            return "basic_bot"

# ==============================================================================
#           NEURAL MEMORY SYSTEM
# ==============================================================================

def init_neural_memory(user_id):
    """Inicializa memoria neuronal para usuario"""
    try:
        with engine.connect() as conn:
            conn.execute(
                text("""
                    INSERT INTO neural_memory (
                        user_id, created_at
                    ) VALUES (
                        :user_id, NOW()
                    )
                """),
                {"user_id": user_id}
            )
            conn.commit()
    except Exception as e:
        print(f"Error initializing neural memory: {e}")

def save_neural_interaction(user_id, interaction_data):
    """Guarda interacción en memoria neuronal"""
    try:
        with engine.connect() as conn:
            conn.execute(
                text("""
                    INSERT INTO neural_interactions (
                        user_id, interaction_data, created_at
                    ) VALUES (
                        :user_id, :data, NOW()
                    )
                """),
                {
                    "user_id": user_id,
                    "data": json.dumps(interaction_data)
                }
            )
            conn.commit()
    except Exception as e:
        print(f"Error saving interaction: {e}")

def update_neural_memory(user_id, interaction_data):
    """Actualiza memoria neuronal con nueva interacción"""
    try:
        # Extraer keywords y contexto
        keywords = intelligent_keyword_extraction(
            interaction_data.get('input', ''),
            interaction_data.get('context', {})
        )
        
        with engine.connect() as conn:
            conn.execute(
                text("""
                    UPDATE neural_memory 
                    SET 
                        keywords = array_append(keywords, :keywords),
                        last_updated = NOW()
                    WHERE user_id = :user_id
                """),
                {
                    "user_id": user_id,
                    "keywords": keywords
                }
            )
            conn.commit()
    except Exception as e:
        print(f"Error updating neural memory: {e}")

def get_neural_memory(user_id):
    """Obtiene memoria neuronal del usuario"""
    try:
        with engine.connect() as conn:
            result = conn.execute(
                text("""
                    SELECT * FROM neural_memory 
                    WHERE user_id = :user_id
                """),
                {"user_id": user_id}
            ).fetchone()
            
            if result:
                return dict(result)
            return None
    except Exception as e:
        print(f"Error getting neural memory: {e}")
        return None

def intelligent_keyword_extraction(query, user_context):
    """Extrae keywords inteligentemente usando Gemini"""
    try:
        prompt = f"""
        Extract the most relevant keywords from this text, considering the context:
        
        Text: {query}
        Context: {user_context}
        
        Return only the keywords, separated by commas.
        """
        
        response = genai.generate_content(
            model=MODEL_NAME,
            contents=[prompt]
        )
        
        keywords = [k.strip() for k in response.text.split(',')]
        return keywords
    except Exception as e:
        print(f"Error extracting keywords: {e}")
        return []

# ==============================================================================
#           PROJECT MANAGEMENT ENDPOINTS
# ==============================================================================

@app.route('/projects', methods=['GET'])
@require_auth
def get_user_projects(user):
    """Obtiene todos los proyectos del usuario autenticado"""
    try:
        with engine.connect() as conn:
            result = conn.execute(
                text("""
                    SELECT id, name, description, industry, stage, location, 
                           website, is_active, created_at, updated_at, kpi_data, status
                    FROM projects 
                    WHERE user_id = :user_id 
                    ORDER BY created_at DESC
                """),
                {"user_id": user['id']}
            ).fetchall()
            
            projects = [dict(row) for row in result]
            return jsonify({
                "success": True,
                "projects": projects,
                "count": len(projects)
            })
            
    except Exception as e:
        print(f"❌ Error getting projects: {e}")
        return jsonify({"error": "Could not fetch projects"}), 500

@app.route('/projects', methods=['POST'])
@require_auth
def create_project(user):
    """Crea un nuevo proyecto para el usuario"""
    try:
        data = request.get_json()
        
        # Validación de campos requeridos
        if not data or 'name' not in data:
            return jsonify({'error': 'Project name is required'}), 400
        
        if len(data['name'].strip()) < 2:
            return jsonify({'error': 'Project name must be at least 2 characters'}), 400
        
        project_id = str(uuid.uuid4())
        
        with engine.connect() as conn:
            # Crear proyecto
            conn.execute(
                text("""
                    INSERT INTO projects (
                        id, user_id, name, description, industry, stage, 
                        location, website, is_active, created_at, updated_at
                    ) VALUES (
                        :id, :user_id, :name, :description, :industry, :stage,
                        :location, :website, true, NOW(), NOW()
                    )
                """),
                {
                    "id": project_id,
                    "user_id": user['id'],
                    "name": data['name'].strip(),
                    "description": data.get('description', '').strip(),
                    "industry": data.get('industry', ''),
                    "stage": data.get('stage', 'idea'),
                    "location": data.get('location', ''),
                    "website": data.get('website', '')
                }
            )
            
            # Inicializar neural memory para el proyecto
            conn.execute(
                text("""
                    INSERT INTO neural_memory (user_id, project_id, memory_data, created_at, updated_at)
                    VALUES (:user_id, :project_id, '{}', NOW(), NOW())
                """),
                {"user_id": user['id'], "project_id": project_id}
            )
            
            conn.commit()
        
        return jsonify({
            "success": True,
            "message": "Project created successfully",
            "project_id": project_id
        }), 201
        
    except Exception as e:
        print(f"❌ Error creating project: {e}")
        return jsonify({"error": "Could not create project"}), 500

@app.route('/projects/<project_id>', methods=['GET'])
@require_auth
def get_project(user, project_id):
    """Obtiene un proyecto específico del usuario"""
    try:
        with engine.connect() as conn:
            result = conn.execute(
                text("""
                    SELECT p.*, nm.memory_data
                    FROM projects p
                    LEFT JOIN neural_memory nm ON p.id = nm.project_id
                    WHERE p.id = :project_id AND p.user_id = :user_id
                """),
                {"project_id": project_id, "user_id": user['id']}
            ).fetchone()
            
            if not result:
                return jsonify({"error": "Project not found"}), 404
            
            project_data = dict(result)
            if project_data['memory_data']:
                try:
                    project_data['neural_memory'] = json.loads(project_data['memory_data'])
                except:
                    project_data['neural_memory'] = {}
            
            return jsonify({
                "success": True,
                "project": project_data
            })
            
    except Exception as e:
        print(f"❌ Error getting project: {e}")
        return jsonify({"error": "Could not fetch project"}), 500

@app.route('/projects/<project_id>', methods=['PUT'])
@require_auth
def update_project(user, project_id):
    """Actualiza un proyecto del usuario"""
    try:
        data = request.get_json()
        
        with engine.connect() as conn:
            # Verificar que el proyecto pertenece al usuario
            project_check = conn.execute(
                text("SELECT id FROM projects WHERE id = :project_id AND user_id = :user_id"),
                {"project_id": project_id, "user_id": user['id']}
            ).fetchone()
            
            if not project_check:
                return jsonify({"error": "Project not found"}), 404
            
            # Construir query de actualización dinámicamente
            update_fields = []
            update_params = {"project_id": project_id}
            
            allowed_fields = ['name', 'description', 'industry', 'stage', 'location', 'website', 'status']
            for field in allowed_fields:
                if field in data and data[field] is not None:
                    update_fields.append(f"{field} = :{field}")
                    update_params[field] = str(data[field]).strip() if isinstance(data[field], str) else data[field]
            
            if update_fields:
                update_fields.append("updated_at = NOW()")
                query = f"UPDATE projects SET {', '.join(update_fields)} WHERE id = :project_id"
                
                conn.execute(text(query), update_params)
                conn.commit()
        
        return jsonify({
            "success": True,
            "message": "Project updated successfully"
        })
        
    except Exception as e:
        print(f"❌ Error updating project: {e}")
        return jsonify({"error": "Could not update project"}), 500

@app.route('/projects/<project_id>', methods=['DELETE'])
@require_auth
def delete_project(user, project_id):
    """Elimina un proyecto del usuario (soft delete)"""
    try:
        with engine.connect() as conn:
            # Verificar que el proyecto pertenece al usuario
            project_check = conn.execute(
                text("SELECT id FROM projects WHERE id = :project_id AND user_id = :user_id"),
                {"project_id": project_id, "user_id": user['id']}
            ).fetchone()
            
            if not project_check:
                return jsonify({"error": "Project not found"}), 404
            
            # Soft delete (marcar como inactivo)
            conn.execute(
                text("UPDATE projects SET is_active = false, updated_at = NOW() WHERE id = :project_id"),
                {"project_id": project_id}
            )
            conn.commit()
        
        return jsonify({
            "success": True,
            "message": "Project deleted successfully"
        })
        
    except Exception as e:
        print(f"❌ Error deleting project: {e}")
        return jsonify({"error": "Could not delete project"}), 500

# ==============================================================================
#           DOCUMENTS ENDPOINTS
# ==============================================================================

@app.route('/documents', methods=['GET'])
@require_auth
def get_user_documents_endpoint(user):
    """Obtiene documentos generados por el usuario"""
    try:
        project_id = request.args.get('project_id')
        document_type = request.args.get('type')
        limit = int(request.args.get('limit', 20))
        
        # Construir query base
        query = """
            SELECT id, bot_used, document_type, title, format, metadata,
                   credits_used, created_at, download_count, is_public, project_id
            FROM generated_documents 
            WHERE user_id = :user_id
        """
        params = {"user_id": user['id']}
        
        # Filtros opcionales
        if project_id:
            query += " AND project_id = :project_id"
            params["project_id"] = project_id
            
        if document_type:
            query += " AND document_type = :document_type"
            params["document_type"] = document_type
        
        query += " ORDER BY created_at DESC LIMIT :limit"
        params["limit"] = limit
        
        with engine.connect() as conn:
            result = conn.execute(text(query), params).fetchall()
            
            documents = []
            for doc in result:
                doc_dict = dict(doc)
                doc_dict['created_at'] = doc_dict['created_at'].isoformat()
                documents.append(doc_dict)
        
        return jsonify({
            "success": True,
            "documents": documents,
            "count": len(documents)
        })
        
    except Exception as e:
        print(f"❌ Error getting documents: {e}")
        return jsonify({"error": "Could not fetch documents"}), 500

# ==============================================================================
#           ROUTES
# ==============================================================================

@app.route('/')
def home():
    """Home endpoint"""
    return jsonify({
        'status': 'online',
        'version': '2.0.0',
        'message': '0Bullshit Backend API',
        'auth_methods': ['manual', 'google'],
        'database_connected': engine is not None,
        'google_auth_enabled': GOOGLE_CLIENT_ID is not None
    })

@app.route('/health')
def health_check():
    """Detailed health check"""
    try:
        # Test database connection
        if engine:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            db_status = "connected"
        else:
            db_status = "disconnected"
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'database': db_status,
            'google_auth': 'enabled' if GOOGLE_CLIENT_ID else 'disabled',
            'gemini_api': 'enabled' if GEMINI_API_KEY else 'disabled',
            'environment': 'production' if 'render.com' in os.environ.get('RENDER_EXTERNAL_URL', '') else 'development'
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 500

@app.route('/auth/register', methods=['POST'])
def register():
    """Registro de usuario"""
    try:
        data = request.get_json()
        required_fields = ['email', 'password', 'first_name', 'last_name']
        
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Verificar si email ya existe
        existing_user = get_user_by_email(data['email'])
        if existing_user:
            return jsonify({'error': 'Email already registered'}), 400
        
        # Crear usuario
        user_id = create_user(
            data['email'],
            data['password'],
            data['first_name'],
            data['last_name']
        )
        
        if not user_id:
            return jsonify({'error': 'Error creating user'}), 500
        
        # Inicializar memoria neuronal
        init_neural_memory(user_id)
        
        # Generar token
        token = generate_jwt_token(user_id)
        
        return jsonify({
            'message': 'User registered successfully',
            'token': token,
            'user_id': user_id
        })
        
    except Exception as e:
        print(f"Error in register: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/auth/login', methods=['POST'])
def login():
    """Login de usuario"""
    try:
        data = request.get_json()
        if not data or 'email' not in data or 'password' not in data:
            return jsonify({'error': 'Email and password are required'}), 400
        
        user = get_user_by_email(data['email'])
        if not user:
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Verificar que sea usuario manual (no Google)
        if user.get('auth_provider') != 'manual':
            return jsonify({'error': 'Please use Google Sign-In for this account'}), 401
        
        if not verify_password(data['password'], user['password_hash']):
            return jsonify({'error': 'Invalid credentials'}), 401
        
        token = generate_jwt_token(user['id'])
        
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'token': token,
            'user': {
                'id': user['id'],
                'email': user['email'],
                'first_name': user['first_name'],
                'last_name': user['last_name'],
                'subscription_plan': user['subscription_plan'],
                'credits': user['credits'],
                'auth_provider': user['auth_provider']
            }
        })
        
    except Exception as e:
        print(f"Error in login: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/auth/google', methods=['POST'])
def google_auth():
    """🔥 ENDPOINT GOOGLE AUTH ARREGLADO"""
    try:
        print("🚀 Google auth endpoint called")
        data = request.get_json()
        
        if not data or not data.get('token'):
            print("❌ No token provided")
            return jsonify({'error': 'Google token is required'}), 400
        
        access_token = data['token']
        print(f"🔑 Received access token (preview): {access_token[:20]}...")
        
        # 🔥 AQUÍ ESTABA EL BUG - Ahora usamos la función arreglada
        user_info = verify_google_access_token(access_token)
        
        if not user_info:
            print("❌ Failed to verify Google token")
            return jsonify({'error': 'Invalid Google token'}), 401
        
        print(f"✅ Google token verified for user: {user_info['email']}")
        
        # Extraer información del usuario
        google_id = user_info['google_id']
        email = user_info['email']
        first_name = user_info['first_name']
        last_name = user_info['last_name']
        
        # Buscar usuario existente por Google ID
        user = get_user_by_google_id(google_id)
        
        if not user:
            # Buscar por email (puede ser un usuario manual existente)
            user = get_user_by_email(email)
            
            if user:
                # Usuario existe pero no tiene Google ID - actualizar
                try:
                    with engine.connect() as conn:
                        conn.execute(
                            text("""
                                UPDATE users 
                                SET google_id = :google_id, auth_provider = 'google'
                                WHERE id = :user_id
                            """),
                            {"google_id": google_id, "user_id": user['id']}
                        )
                        conn.commit()
                        user['google_id'] = google_id
                        user['auth_provider'] = 'google'
                        print(f"✅ Updated existing user with Google ID: {user['id']}")
                except Exception as e:
                    print(f"❌ Error updating user with Google ID: {e}")
            else:
                # Crear nuevo usuario con Google
                user_id = create_user(
                    email=email,
                    first_name=first_name,
                    last_name=last_name,
                    auth_provider='google',
                    google_id=google_id
                )
                if not user_id:
                    return jsonify({'error': 'Failed to create user'}), 500
                
                user = get_user_by_id(user_id)
                print(f"✅ Created new Google user: {user_id}")
        
        # Generar token JWT
        token = generate_jwt_token(user['id'])
        
        print(f"🎉 Google authentication successful for: {user['email']}")
        
        return jsonify({
            'success': True,
            'message': 'Google authentication successful',
            'token': token,
            'user': {
                'id': str(user['id']),
                'email': user['email'],
                'first_name': user['first_name'],
                'last_name': user['last_name'],
                'subscription_plan': user['subscription_plan'],
                'credits': user['credits'],
                'auth_provider': user['auth_provider']
            }
        })
        
    except Exception as e:
        print(f"❌ Error in Google auth: {e}")
        return jsonify({'error': 'Google authentication failed'}), 500

@app.route('/user/profile', methods=['GET'])
@require_auth
def get_profile(user):
    """Obtiene perfil del usuario"""
    try:
        return jsonify({
            'id': user['id'],
            'email': user['email'],
            'first_name': user['first_name'],
            'last_name': user['last_name'],
            'subscription_plan': user['subscription_plan'],
            'credits': user['credits'],
            'created_at': user['created_at']
        })
    except Exception as e:
        print(f"Error getting profile: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/credits/balance', methods=['GET'])
@require_auth
def get_credits_balance(user):
    """Obtiene balance de créditos"""
    try:
        return jsonify({
            'credits': user['credits'],
            'plan': user['subscription_plan']
        })
    except Exception as e:
        print(f"Error getting credits: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/chat/bot', methods=['POST'])
@require_auth
def chat_with_bot(user):
    """Procesa mensaje del usuario y retorna respuesta del bot"""
    try:
        data = request.get_json()
        if not data or 'message' not in data:
            return jsonify({'error': 'Message is required'}), 400
            
        # Obtener project context si se proporciona
        project_id = data.get('project_id')
        project_context = {}
        
        if project_id:
            try:
                with engine.connect() as conn:
                    # Obtener info del proyecto
                    project_result = conn.execute(
                        text("""
                            SELECT p.*, nm.memory_data 
                            FROM projects p
                            LEFT JOIN neural_memory nm ON p.id = nm.project_id
                            WHERE p.id = :project_id AND p.user_id = :user_id
                        """),
                        {"project_id": project_id, "user_id": user['id']}
                    ).fetchone()
                    
                    if project_result:
                        project_context = dict(project_result)
                        if project_context.get('memory_data'):
                            try:
                                project_context['neural_memory'] = json.loads(project_context['memory_data'])
                            except:
                                project_context['neural_memory'] = {}
            except Exception as e:
                print(f"⚠️ Warning: Could not load project context: {e}")
        
        # Verificar créditos
        if not has_sufficient_credits(user['id'], CREDIT_COSTS['basic_bot']):
            return jsonify({
                'error': 'Insufficient credits',
                'required': CREDIT_COSTS['basic_bot'],
                'available': get_user_credits(user['id'])
            }), 402
            
        # Procesar mensaje con bot_manager
        enhanced_context = {
            'user_id': user['id'],
            'user_plan': user['subscription_plan'],
            'project_id': project_id,
            'project_context': project_context,
            **data.get('context', {})
        }
        
        response = bot_manager.process_user_request(
            data['message'],
            enhanced_context,
            user['id']
        )
        
        return jsonify(response)
        
    except Exception as e:
        print(f"❌ Error in chat_with_bot: {e}")
        return jsonify({'error': 'Could not process message'}), 500

@app.route('/bots/available', methods=['GET'])
@require_auth
def get_available_bots(user):
    """Obtiene lista de bots disponibles"""
    try:
        plan = user['subscription_plan']
        available_bots = []
        
        # Bots básicos (todos los planes)
        available_bots.extend([
            'basic_bot',
            'advanced_bot',
            'expert_bot',
            'document_generation'
        ])
        
        # Bots de Growth plan
        if plan in ['growth', 'pro']:
            available_bots.extend([
                'investor_search_result',
                'employee_search_result'
            ])
        
        # Bots de Pro plan
        if plan == 'pro':
            available_bots.extend([
                'template_generation',
                'unipile_message',
                'automated_sequence'
            ])
        
        return jsonify({
            'available_bots': available_bots,
            'credit_costs': {bot: CREDIT_COSTS[bot] for bot in available_bots}
        })
        
    except Exception as e:
        print(f"Error getting bots: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/search/investors', methods=['POST'])
@require_auth
@require_plan('growth')
def search_investors(user):
    """Búsqueda de inversores"""
    try:
        data = request.get_json()
        if not data or 'query' not in data:
            return jsonify({'error': 'Search query is required'}), 400
        
        # Verificar créditos
        required_credits = CREDIT_COSTS['investor_search_result']
        if user['credits'] < required_credits:
            return jsonify({
                'error': 'Insufficient credits',
                'required': required_credits,
                'available': user['credits']
            }), 402
        
        # Realizar búsqueda
        results = ml_investor_search(
            data['query'],
            data.get('preferences', {})
        )
        
        # Cobrar créditos
        charge_credits(user['id'], required_credits)
        
        return jsonify({
            'results': results,
            'credits_used': required_credits
        })
        
    except Exception as e:
        print(f"Error searching investors: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/search/employees', methods=['POST'])
@require_auth
@require_plan('growth')
def search_employees(user):
    """Búsqueda de empleados"""
    try:
        data = request.get_json()
        if not data or 'query' not in data:
            return jsonify({'error': 'Search query is required'}), 400
        
        # Verificar créditos
        required_credits = CREDIT_COSTS['employee_search_result']
        if user['credits'] < required_credits:
            return jsonify({
                'error': 'Insufficient credits',
                'required': required_credits,
                'available': user['credits']
            }), 402
        
        # Realizar búsqueda
        results = ml_investor_search(  # Reutilizamos la función de búsqueda
            data['query'],
            data.get('preferences', {}),
            search_type='employees'
        )
        
        # Cobrar créditos
        charge_credits(user['id'], required_credits)
        
        return jsonify({
            'results': results,
            'credits_used': required_credits
        })
        
    except Exception as e:
        print(f"Error searching employees: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/outreach/generate-template', methods=['POST'])
@require_auth
@require_plan('pro')
def generate_outreach_template(user):
    """Genera template de outreach"""
    try:
        data = request.get_json()
        if not data or 'context' not in data:
            return jsonify({'error': 'Context is required'}), 400
        
        # Verificar créditos
        required_credits = CREDIT_COSTS['template_generation']
        if user['credits'] < required_credits:
            return jsonify({
                'error': 'Insufficient credits',
                'required': required_credits,
                'available': user['credits']
            }), 402
        
        # Generar template
        prompt = f"""
        Generate an outreach template based on this context:
        
        {data['context']}
        
        The template should be professional and personalized.
        """
        
        response = genai.generate_content(
            model=MODEL_NAME,
            contents=[prompt]
        )
        
        # Cobrar créditos
        charge_credits(user['id'], required_credits)
        
        return jsonify({
            'template': response.text,
            'credits_used': required_credits
        })
        
    except Exception as e:
        print(f"Error generating template: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/admin/stats', methods=['GET'])
@require_auth
def get_admin_stats(user):
    """Obtiene estadísticas de admin"""
    try:
        # Verificar si es admin
        if user['subscription_plan'] != 'pro':
            return jsonify({'error': 'Admin access required'}), 403
        
        with engine.connect() as conn:
            # Total usuarios
            total_users = conn.execute(
                text("SELECT COUNT(*) FROM users")
            ).scalar()
            
            # Usuarios por plan
            users_by_plan = conn.execute(
                text("""
                    SELECT subscription_plan, COUNT(*) 
                    FROM users 
                    GROUP BY subscription_plan
                """)
            ).fetchall()
            
            # Total créditos en sistema
            total_credits = conn.execute(
                text("SELECT SUM(credits) FROM users")
            ).scalar()
            
            # Transacciones recientes
            recent_transactions = conn.execute(
                text("""
                    SELECT * FROM credit_transactions 
                    ORDER BY created_at DESC 
                    LIMIT 10
                """)
            ).fetchall()
        
        return jsonify({
            'total_users': total_users,
            'users_by_plan': dict(users_by_plan),
            'total_credits': total_credits,
            'recent_transactions': [dict(t) for t in recent_transactions]
        })
        
    except Exception as e:
        print(f"Error getting stats: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/subscription/upgrade', methods=['POST'])
@require_auth
def upgrade_subscription(user):
    """Actualiza el plan de suscripción"""
    try:
        data = request.get_json()
        if not data or 'plan' not in data:
            return jsonify({'error': 'Plan is required'}), 400
            
        new_plan = data['plan']
        if new_plan not in SUBSCRIPTION_PLANS:
            return jsonify({'error': 'Invalid plan'}), 400
            
        if new_plan == user['subscription_plan']:
            return jsonify({'error': 'Already subscribed to this plan'}), 400
            
        success = update_subscription_plan(user['id'], new_plan)
        if not success:
            return jsonify({'error': 'Failed to update subscription'}), 500
            
        return jsonify({
            'message': f'Successfully upgraded to {new_plan} plan',
            'new_plan': new_plan,
            'credits_added': SUBSCRIPTION_PLANS[new_plan]['launch_credits']
        })
        
    except Exception as e:
        print(f"Error upgrading subscription: {e}")
        return jsonify({'error': str(e)}), 500

# ==============================================================================
#           GOOGLE AUTH FUNCTIONS - ARREGLADAS
# ==============================================================================

def verify_google_access_token(access_token):
    try:
        print(f"🔍 Verifying Google access token...")
        
        # Usar userinfo endpoint en lugar de tokeninfo
        response = requests.get(
            f'https://www.googleapis.com/oauth2/v2/userinfo?access_token={access_token}',
            timeout=10
        )
        
        print(f"📡 Google API response status: {response.status_code}")
        
        if response.status_code != 200:
            print(f"❌ Google API error: {response.text}")
            return None
        
        user_info = response.json()
        print(f"👤 User info received: {user_info}")
        
        return {
            'google_id': user_info.get('id'),
            'email': user_info.get('email'),
            'first_name': user_info.get('given_name', ''),
            'last_name': user_info.get('family_name', ''),
            'picture': user_info.get('picture', ''),
            'verified_email': user_info.get('verified_email', False)
        }
        
    except Exception as e:
        print(f"❌ Error verifying Google token: {e}")
        return None

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))
