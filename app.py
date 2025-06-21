# -*- coding: utf-8 -*-
"""
0Bullshit Backend v2.0 - Sistema Gamificado con 60 Bots
Sistema de créditos, suscripciones y memoria neuronal
VERSIÓN COMPLETAMENTE ARREGLADA - Register funcionando 100%
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
#           AUTHENTICATION & USER MANAGEMENT - ARREGLADO
# ==============================================================================

def get_bot_credit_cost(bot_id):
    """Obtiene el costo en créditos de un bot - ARREGLADO"""
    return CREDIT_COSTS.get(bot_id, 5)

def hash_password(password):
    """Hash password usando bcrypt - ARREGLADO"""
    if not password:
        return None
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password, hashed):
    """Verifica password contra hash - ARREGLADO"""
    if not password or not hashed:
        return False
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except Exception as e:
        print(f"Error verifying password: {e}")
        return False

def generate_jwt_token(user_id):
    """Genera JWT token para el usuario - ARREGLADO"""
    try:
        payload = {
            'user_id': str(user_id),
            'exp': datetime.utcnow() + timedelta(days=7),
            'iat': datetime.utcnow()
        }
        return jwt.encode(payload, JWT_SECRET, algorithm='HS256')
    except Exception as e:
        print(f"Error generating JWT: {e}")
        return None

def verify_jwt_token(token):
    """Verifica y decodifica JWT token - ARREGLADO"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return payload['user_id']
    except jwt.ExpiredSignatureError:
        print("Token expired")
        return None
    except jwt.InvalidTokenError:
        print("Invalid token")
        return None
    except Exception as e:
        print(f"Error verifying token: {e}")
        return None

def require_auth(f):
    """Decorator para endpoints que requieren autenticación - ARREGLADO"""
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
    """Obtiene usuario por ID - ARREGLADO"""
    try:
        with engine.connect() as conn:
            result = conn.execute(
                text("""
                    SELECT id, email, password_hash, first_name, last_name, 
                           subscription_plan, credits, auth_provider, google_id, 
                           is_active, is_admin, created_at, updated_at
                    FROM users 
                    WHERE id = :user_id
                """),
                {"user_id": user_id}
            ).fetchone()
            
            if result:
                return {
                    'id': str(result[0]),
                    'email': result[1],
                    'password_hash': result[2],
                    'first_name': result[3] or '',
                    'last_name': result[4] or '',
                    'subscription_plan': result[5] or 'free',
                    'credits': result[6] or 100,
                    'auth_provider': result[7] or 'manual',
                    'google_id': result[8],
                    'is_active': result[9] if len(result) > 9 else True,
                    'is_admin': result[10] if len(result) > 10 else False,
                    'created_at': result[11] if len(result) > 11 else None,
                    'updated_at': result[12] if len(result) > 12 else None
                }
            return None
    except Exception as e:
        print(f"Error getting user by ID: {e}")
        return None

def get_user_by_email(email):
    """Obtiene usuario por email - ARREGLADO"""
    try:
        with engine.connect() as conn:
            result = conn.execute(
                text("""
                    SELECT id, email, password_hash, first_name, last_name, 
                           subscription_plan, credits, auth_provider, google_id, 
                           is_active, is_admin, created_at, updated_at
                    FROM users 
                    WHERE email = :email
                """),
                {"email": email}
            ).fetchone()
            
            if result:
                return {
                    'id': str(result[0]),
                    'email': result[1],
                    'password_hash': result[2],
                    'first_name': result[3] or '',
                    'last_name': result[4] or '',
                    'subscription_plan': result[5] or 'free',
                    'credits': result[6] or 100,
                    'auth_provider': result[7] or 'manual',
                    'google_id': result[8],
                    'is_active': result[9] if len(result) > 9 else True,
                    'is_admin': result[10] if len(result) > 10 else False,
                    'created_at': result[11] if len(result) > 11 else None,
                    'updated_at': result[12] if len(result) > 12 else None
                }
            return None
    except Exception as e:
        print(f"Error getting user by email: {e}")
        return None

def get_user_by_google_id(google_id):
    """Obtiene usuario por Google ID - ARREGLADO"""
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
                    'password_hash': result[2],
                    'first_name': result[3] or '',
                    'last_name': result[4] or '',
                    'subscription_plan': result[5] or 'free',
                    'credits': result[6] or 100,
                    'auth_provider': result[7] or 'manual',
                    'google_id': result[8],
                    'is_active': result[9] if len(result) > 9 else True,
                    'is_admin': result[10] if len(result) > 10 else False,
                    'created_at': result[11] if len(result) > 11 else None
                }
            return None
    except Exception as e:
        print(f"Error getting user by Google ID: {e}")
        return None

def create_user(email, password=None, first_name="", last_name="", auth_provider="manual", google_id=None):
    """Crea nuevo usuario - ARREGLADO"""
    try:
        user_id = str(uuid.uuid4())
        password_hash = hash_password(password) if password else None
        
        # Creditos iniciales por plan
        initial_credits = SUBSCRIPTION_PLANS['free']['launch_credits']
        
        with engine.connect() as conn:
            conn.execute(
                text("""
                    INSERT INTO users (
                        id, email, password_hash, first_name, last_name,
                        subscription_plan, credits, auth_provider, google_id, 
                        is_active, is_admin, created_at, updated_at
                    ) VALUES (
                        :id, :email, :password_hash, :first_name, :last_name,
                        'free', :credits, :auth_provider, :google_id, 
                        true, false, NOW(), NOW()
                    )
                """),
                {
                    "id": user_id,
                    "email": email,
                    "password_hash": password_hash,
                    "first_name": first_name,
                    "last_name": last_name,
                    "credits": initial_credits,
                    "auth_provider": auth_provider,
                    "google_id": google_id
                }
            )
            conn.commit()
            print(f"✅ User created successfully: {user_id}")
            return user_id
    except Exception as e:
        print(f"❌ Error creating user: {e}")
        return None

def validate_password_strength(password):
    """Valida que la contraseña cumpla con los requisitos - ARREGLADO"""
    if not password:
        return False, "Password is required"
    
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number"
    
    return True, "Password is valid"

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
                        id, user_id, amount, transaction_type, description, created_at
                    ) VALUES (
                        :id, :user_id, :amount, :type, :description, NOW()
                    )
                """),
                {
                    "id": str(uuid.uuid4()),
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
                        credits = credits + :additional_credits,
                        updated_at = NOW()
                    WHERE id = :user_id
                """),
                {
                    "user_id": user_id,
                    "plan": new_plan,
                    "additional_credits": SUBSCRIPTION_PLANS[new_plan]['launch_credits']
                }
            )
            conn.commit()
            return True
    except Exception as e:
        print(f"Error updating subscription: {e}")
        return False

# ==============================================================================
#           NEURAL MEMORY SYSTEM
# ==============================================================================

def init_neural_memory(user_id):
    """Inicializa memoria neuronal para usuario - ARREGLADO"""
    try:
        with engine.connect() as conn:
            # Verificar si ya existe
            existing = conn.execute(
                text("SELECT id FROM neural_memory WHERE user_id = :user_id"),
                {"user_id": user_id}
            ).fetchone()
            
            if not existing:
                conn.execute(
                    text("""
                        INSERT INTO neural_memory (user_id, memory_data, created_at, updated_at)
                        VALUES (:user_id, '{}', NOW(), NOW())
                    """),
                    {"user_id": user_id}
                )
                conn.commit()
                print(f"✅ Neural memory initialized for user: {user_id}")
    except Exception as e:
        print(f"❌ Error initializing neural memory: {e}")

def save_neural_interaction(user_id, interaction_data):
    """Guarda interacción en memoria neuronal"""
    try:
        with engine.connect() as conn:
            conn.execute(
                text("""
                    INSERT INTO neural_interactions (
                        id, user_id, bot_used, user_input, bot_output, 
                        credits_charged, context_data, created_at
                    ) VALUES (
                        :id, :user_id, :bot_used, :user_input, :bot_output,
                        :credits_charged, :context_data, NOW()
                    )
                """),
                {
                    "id": str(uuid.uuid4()),
                    "user_id": user_id,
                    "bot_used": interaction_data.get('bot', 'unknown'),
                    "user_input": interaction_data.get('input', ''),
                    "bot_output": interaction_data.get('response', ''),
                    "credits_charged": interaction_data.get('credits_used', 0),
                    "context_data": json.dumps(interaction_data.get('context', {}))
                }
            )
            conn.commit()
    except Exception as e:
        print(f"Error saving interaction: {e}")

def get_neural_memory(user_id):
    """Obtiene memoria neuronal del usuario"""
    try:
        with engine.connect() as conn:
            result = conn.execute(
                text("""
                    SELECT memory_data FROM neural_memory 
                    WHERE user_id = :user_id
                """),
                {"user_id": user_id}
            ).fetchone()
            
            if result and result[0]:
                return json.loads(result[0])
            return {}
    except Exception as e:
        print(f"Error getting neural memory: {e}")
        return {}

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
            
            # Generar respuesta usando Gemini
            prompt = f"""
            Eres un asistente de IA especializado en startups y emprendimiento.
            
            Entrada del usuario: {user_input}
            Contexto: {user_context}
            
            Proporciona una respuesta útil, práctica y accionable.
            """
            
            response = genai.generate_content(
                model=MODEL_NAME,
                contents=[prompt]
            )
            
            # Cobrar créditos
            charge_credits(user_id, required_credits)
            
            # Guardar en memoria neuronal
            save_neural_interaction(user_id, {
                'bot': selected_bot,
                'input': user_input,
                'response': response.text,
                'credits_used': required_credits,
                'context': user_context
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

# Instanciar bot manager global
bot_manager = BotManager()

# ==============================================================================
#           GOOGLE AUTH FUNCTIONS - ARREGLADAS
# ==============================================================================

def verify_google_access_token(access_token):
    """Verifica Google access token - ARREGLADO"""
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

# Security Headers Middleware
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# ==============================================================================
#           ROUTES - ARREGLADAS
# ==============================================================================

@app.route('/')
def home():
    """Home endpoint"""
    return jsonify({
        'status': 'online',
        'version': '2.0.0',
        'message': '0Bullshit Backend API - FIXED VERSION',
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

@app.route('/auth/test', methods=['GET'])
def test_auth():
    """Test endpoint para verificar que el sistema funciona"""
    try:
        return jsonify({
            'status': 'ok',
            'message': 'Auth system is working',
            'database_connected': engine is not None,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/auth/register', methods=['POST'])
def register():
    """Registro de usuario - COMPLETAMENTE ARREGLADO"""
    try:
        print("🚀 Register endpoint called")
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        print(f"📥 Received data: {data}")
        
        # Validar campos requeridos
        required_fields = ['email', 'password', 'first_name', 'last_name']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Validar formato de email
        email = data['email'].lower().strip()
        if '@' not in email or '.' not in email:
            return jsonify({'error': 'Invalid email format'}), 400
        
        # Validar contraseña
        password = data['password']
        is_valid, message = validate_password_strength(password)
        if not is_valid:
            return jsonify({'error': message}), 400
        
        # Verificar si email ya existe
        existing_user = get_user_by_email(email)
        if existing_user:
            return jsonify({'error': 'Email already registered'}), 400
        
        # Crear usuario
        user_id = create_user(
            email=email,
            password=password,
            first_name=data['first_name'].strip(),
            last_name=data['last_name'].strip()
        )
        
        if not user_id:
            return jsonify({'error': 'Error creating user'}), 500
        
        # Inicializar memoria neuronal
        init_neural_memory(user_id)
        
        # Generar token
        token = generate_jwt_token(user_id)
        if not token:
            return jsonify({'error': 'Error generating token'}), 500
        
        print(f"✅ User registered successfully: {user_id}")
        
        return jsonify({
            'success': True,
            'message': 'User registered successfully',
            'token': token,
            'user_id': user_id,
            'user': {
                'id': user_id,
                'email': email,
                'first_name': data['first_name'],
                'last_name': data['last_name'],
                'subscription_plan': 'free',
                'credits': 100
            }
        }), 201
        
    except Exception as e:
        print(f"❌ Error in register: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@app.route('/auth/login', methods=['POST'])
def login():
    """Login de usuario - ARREGLADO"""
    try:
        print("🚀 Login endpoint called")
        data = request.get_json()
        
        if not data or 'email' not in data or 'password' not in data:
            return jsonify({'error': 'Email and password are required'}), 400
        
        email = data['email'].lower().strip()
        password = data['password']
        
        user = get_user_by_email(email)
        if not user:
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Verificar que sea usuario manual (no Google)
        if user.get('auth_provider') != 'manual':
            return jsonify({'error': 'Please use Google Sign-In for this account'}), 401
        
        if not verify_password(password, user.get('password_hash')):
            return jsonify({'error': 'Invalid credentials'}), 401
        
        token = generate_jwt_token(user['id'])
        if not token:
            return jsonify({'error': 'Error generating token'}), 500
        
        print(f"✅ User logged in successfully: {user['id']}")
        
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
        print(f"❌ Error in login: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@app.route('/auth/google', methods=['POST'])
def google_auth():
    """Google auth endpoint - ARREGLADO"""
    try:
        print("🚀 Google auth endpoint called")
        data = request.get_json()
        
        if not data or not data.get('token'):
            print("❌ No token provided")
            return jsonify({'error': 'Google token is required'}), 400
        
        access_token = data['token']
        print(f"🔑 Received access token (preview): {access_token[:20]}...")
        
        # Verificar token con Google
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
                                SET google_id = :google_id, auth_provider = 'google', updated_at = NOW()
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
                
                # Inicializar memoria neuronal
                init_neural_memory(user_id)
                
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
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'Google authentication failed'}), 500

@app.route('/user/profile', methods=['GET'])
@require_auth
def get_profile(user):
    """Obtiene perfil del usuario"""
    try:
        return jsonify({
            'success': True,
            'user': {
                'id': user['id'],
                'email': user['email'],
                'first_name': user['first_name'],
                'last_name': user['last_name'],
                'subscription_plan': user['subscription_plan'],
                'credits': user['credits'],
                'auth_provider': user['auth_provider'],
                'created_at': user['created_at'].isoformat() if user['created_at'] else None
            }
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
            'success': True,
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
            **data.get('context', {})
        }
        
        response = bot_manager.process_user_request(
            data['message'],
            enhanced_context,
            user['id']
        )
        
        return jsonify({
            'success': True,
            **response
        })
        
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
            'success': True,
            'available_bots': available_bots,
            'credit_costs': {bot: CREDIT_COSTS[bot] for bot in available_bots}
        })
        
    except Exception as e:
        print(f"Error getting bots: {e}")
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
            'success': True,
            'message': f'Successfully upgraded to {new_plan} plan',
            'new_plan': new_plan,
            'credits_added': SUBSCRIPTION_PLANS[new_plan]['launch_credits']
        })
        
    except Exception as e:
        print(f"Error upgrading subscription: {e}")
        return jsonify({'error': str(e)}), 500

# ==============================================================================
#           ADMIN ENDPOINTS PARA GESTIONAR USUARIOS
# ==============================================================================

@app.route('/admin/users', methods=['GET'])
@require_auth
def get_all_users(user):
    """Obtiene todos los usuarios (solo admin)"""
    try:
        # Verificar que sea admin
        if not user.get('is_admin'):
            return jsonify({'error': 'Admin access required'}), 403
        
        with engine.connect() as conn:
            result = conn.execute(
                text("""
                    SELECT id, email, first_name, last_name, subscription_plan, 
                           credits, is_admin, auth_provider, created_at, updated_at
                    FROM users 
                    ORDER BY created_at DESC
                """)
            ).fetchall()
            
            users = []
            for row in result:
                users.append({
                    'id': str(row[0]),
                    'email': row[1],
                    'first_name': row[2],
                    'last_name': row[3],
                    'subscription_plan': row[4],
                    'credits': row[5],
                    'is_admin': row[6],
                    'auth_provider': row[7],
                    'created_at': row[8].isoformat() if row[8] else None,
                    'updated_at': row[9].isoformat() if row[9] else None
                })
        
        return jsonify({
            'success': True,
            'users': users,
            'total_count': len(users)
        })
        
    except Exception as e:
        print(f"❌ Error getting users: {e}")
        return jsonify({'error': 'Could not get users'}), 500

@app.route('/admin/users/<user_id>/upgrade', methods=['POST'])
@require_auth
def upgrade_user_plan(user, user_id):
    """Upgradea plan de usuario (solo admin)"""
    try:
        # Verificar que sea admin
        if not user.get('is_admin'):
            return jsonify({'error': 'Admin access required'}), 403
        
        data = request.get_json()
        new_plan = data.get('plan', 'free')
        add_credits = data.get('add_credits', 0)
        
        if new_plan not in ['free', 'growth', 'pro']:
            return jsonify({'error': 'Invalid plan'}), 400
        
        with engine.connect() as conn:
            # Verificar que el usuario existe
            existing_user = conn.execute(
                text("SELECT id, email FROM users WHERE id = :user_id"),
                {"user_id": user_id}
            ).fetchone()
            
            if not existing_user:
                return jsonify({'error': 'User not found'}), 404
            
            # Actualizar plan y créditos
            conn.execute(
                text("""
                    UPDATE users 
                    SET subscription_plan = :plan,
                        credits = credits + :add_credits,
                        updated_at = NOW()
                    WHERE id = :user_id
                """),
                {
                    "user_id": user_id,
                    "plan": new_plan,
                    "add_credits": add_credits
                }
            )
            conn.commit()
        
        return jsonify({
            'success': True,
            'message': f'User upgraded to {new_plan} plan',
            'user_email': existing_user[1],
            'new_plan': new_plan,
            'credits_added': add_credits
        })
        
    except Exception as e:
        print(f"❌ Error upgrading user: {e}")
        return jsonify({'error': 'Could not upgrade user'}), 500

@app.route('/admin/users/<user_id>/credits', methods=['POST'])
@require_auth
def manage_user_credits(user, user_id):
    """Gestiona créditos de usuario (solo admin)"""
    try:
        # Verificar que sea admin
        if not user.get('is_admin'):
            return jsonify({'error': 'Admin access required'}), 403
        
        data = request.get_json()
        action = data.get('action', 'add')  # add, subtract, set
        amount = data.get('amount', 0)
        
        if action not in ['add', 'subtract', 'set']:
            return jsonify({'error': 'Invalid action'}), 400
        
        if amount < 0:
            return jsonify({'error': 'Amount must be positive'}), 400
        
        with engine.connect() as conn:
            # Verificar que el usuario existe
            existing_user = conn.execute(
                text("SELECT id, email, credits FROM users WHERE id = :user_id"),
                {"user_id": user_id}
            ).fetchone()
            
            if not existing_user:
                return jsonify({'error': 'User not found'}), 404
            
            current_credits = existing_user[2]
            
            # Calcular nuevos créditos
            if action == 'add':
                new_credits = current_credits + amount
            elif action == 'subtract':
                new_credits = max(0, current_credits - amount)
            else:  # set
                new_credits = amount
            
            # Actualizar créditos
            conn.execute(
                text("""
                    UPDATE users 
                    SET credits = :new_credits,
                        updated_at = NOW()
                    WHERE id = :user_id
                """),
                {
                    "user_id": user_id,
                    "new_credits": new_credits
                }
            )
            conn.commit()
        
        return jsonify({
            'success': True,
            'message': f'Credits {action}ed successfully',
            'user_email': existing_user[1],
            'previous_credits': current_credits,
            'new_credits': new_credits,
            'amount_changed': amount
        })
        
    except Exception as e:
        print(f"❌ Error managing credits: {e}")
        return jsonify({'error': 'Could not manage credits'}), 500

@app.route('/admin/create-premium-user', methods=['POST'])
@require_auth
def create_premium_user(user):
    """Crea usuario premium para testing (solo admin)"""
    try:
        # Verificar que sea admin
        if not user.get('is_admin'):
            return jsonify({'error': 'Admin access required'}), 403
        
        data = request.get_json()
        email = data.get('email', f'test{int(time.time())}@premium.com')
        password = data.get('password', 'PremiumTest123!')
        first_name = data.get('first_name', 'Premium')
        last_name = data.get('last_name', 'Tester')
        plan = data.get('plan', 'pro')
        credits = data.get('credits', 500000)
        
        # Verificar si el email ya existe
        existing_user = get_user_by_email(email)
        if existing_user:
            return jsonify({'error': 'Email already exists'}), 400
        
        # Crear usuario premium
        user_id = create_user(
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name
        )
        
        if not user_id:
            return jsonify({'error': 'Could not create user'}), 500
        
        # Actualizar a premium
        with engine.connect() as conn:
            conn.execute(
                text("""
                    UPDATE users 
                    SET subscription_plan = :plan,
                        credits = :credits,
                        is_admin = true,
                        updated_at = NOW()
                    WHERE id = :user_id
                """),
                {
                    "user_id": user_id,
                    "plan": plan,
                    "credits": credits
                }
            )
            conn.commit()
        
        # Inicializar memoria neuronal
        init_neural_memory(user_id)
        
        # Generar token
        token = generate_jwt_token(user_id)
        
        return jsonify({
            'success': True,
            'message': 'Premium user created successfully',
            'user': {
                'id': user_id,
                'email': email,
                'password': password,  # Solo para testing
                'first_name': first_name,
                'last_name': last_name,
                'subscription_plan': plan,
                'credits': credits,
                'is_admin': True
            },
            'token': token
        }), 201
        
    except Exception as e:
        print(f"❌ Error creating premium user: {e}")
        return jsonify({'error': 'Could not create premium user'}), 500

@app.route('/admin/stats', methods=['GET'])
@require_auth
def get_admin_stats(user):
    """Obtiene estadísticas generales (solo admin)"""
    try:
        # Verificar que sea admin
        if not user.get('is_admin'):
            return jsonify({'error': 'Admin access required'}), 403
        
        with engine.connect() as conn:
            # Estadísticas de usuarios
            user_stats = conn.execute(
                text("""
                    SELECT 
                        subscription_plan,
                        COUNT(*) as count,
                        SUM(credits) as total_credits,
                        AVG(credits) as avg_credits
                    FROM users 
                    GROUP BY subscription_plan
                """)
            ).fetchall()
            
            # Total de interacciones
            total_interactions = conn.execute(
                text("SELECT COUNT(*) FROM neural_interactions")
            ).scalar() or 0
            
            # Usuarios activos (últimos 7 días)
            active_users = conn.execute(
                text("""
                    SELECT COUNT(DISTINCT user_id) 
                    FROM neural_interactions 
                    WHERE created_at > NOW() - INTERVAL '7 days'
                """)
            ).scalar() or 0
        
        stats_by_plan = {}
        for row in user_stats:
            stats_by_plan[row[0]] = {
                'count': row[1],
                'total_credits': row[2] or 0,
                'avg_credits': float(row[3]) if row[3] else 0
            }
        
        return jsonify({
            'success': True,
            'stats': {
                'users_by_plan': stats_by_plan,
                'total_interactions': total_interactions,
                'active_users_7d': active_users
            }
        })
        
    except Exception as e:
        print(f"❌ Error getting stats: {e}")
        return jsonify({'error': 'Could not get stats'}), 500

# ==============================================================================
#           MAIN
# ==============================================================================

if __name__ == '__main__':
    print("🔥 0BULLSHIT BACKEND V2.0 - FIXED VERSION LOADED!")
    print("✅ Register endpoint should work perfectly now!")
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)), debug=True)
