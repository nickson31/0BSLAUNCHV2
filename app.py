# -*- coding: utf-8 -*-
"""
0Bullshit Backend v2.0 - CORS ARREGLADO DEFINITIVAMENTE
Sistema de 60 bots, memoria neuronal, créditos y chat sessions
VERSIÓN FINAL SIN PROBLEMAS DE CORS
"""

# ==============================================================================
#           IMPORTS
# ==============================================================================

print("1. Loading libraries...")
from flask import Flask, request, jsonify, session, redirect, url_for, make_response
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
import tempfile
from werkzeug.utils import secure_filename
from werkzeug.datastructures import FileStorage
import PyPDF2
import docx
import mimetypes

# Google Auth
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

# ==============================================================================
#           CONFIGURATION
# ==============================================================================

print("2. Configuring application...")
app = Flask(__name__)

# ==================== CORS KILLER - CONFIGURACIÓN NUCLEAR ====================
print("🛡️ Configurando CORS KILLER...")

CORS(app, resources={
    r"/*": {
        "origins": "*",
        "methods": "*",
        "allow_headers": "*"
    }
})

# Rate Limiter Configuration
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

app.secret_key = os.environ.get('JWT_SECRET', secrets.token_hex(16))
warnings.filterwarnings('ignore')

# Environment Variables
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
DATABASE_URL = os.environ.get("DATABASE_URL")
JWT_SECRET = os.environ.get("JWT_SECRET", secrets.token_hex(32))
UNIPILE_API_KEY = os.environ.get("UNIPILE_API_KEY")
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
FRONTEND_URL = os.environ.get("FRONTEND_URL", "https://v0-0-bull-shit.vercel.app")

# Debug info
print(f"🔐 GOOGLE_CLIENT_ID configured: {'✅' if GOOGLE_CLIENT_ID else '❌'}")
print(f"🗄️ DATABASE_URL configured: {'✅' if DATABASE_URL else '❌'}")
print(f"🔑 JWT_SECRET configured: {'✅' if JWT_SECRET else '❌'}")
print(f"🤖 GEMINI_API_KEY configured: {'✅' if GEMINI_API_KEY else '❌'}")

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
#           CORS MIDDLEWARE - CONFIGURACIÓN DEFINITIVA
# ==============================================================================

@app.before_request
def handle_options():
    if request.method == "OPTIONS":
        response = make_response()
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Headers"] = "*" 
        response.headers["Access-Control-Allow-Methods"] = "*"
        return response

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "*"
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

def get_bot_credit_cost(bot_id):
    """Obtiene el costo en créditos de un bot"""
    return CREDIT_COSTS.get(bot_id, 5)

def hash_password(password):
    """Hash password usando bcrypt"""
    if not password:
        return None
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password, hashed):
    """Verifica password contra hash"""
    if not password or not hashed:
        return False
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except Exception as e:
        print(f"Error verifying password: {e}")
        return False

def generate_jwt_token(user_id):
    """Genera JWT token para el usuario"""
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
    """Verifica y decodifica JWT token"""
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

def get_user_by_id(user_id):
    """Obtiene usuario por ID - CORREGIDO para tu esquema EXACTO"""
    try:
        with engine.connect() as conn:
            result = conn.execute(
                text("""
                    SELECT id, email, password_hash, first_name, last_name, 
                           plan, credits, auth_provider, google_id, 
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
                    'subscription_plan': result[5] or 'free',  # Mapear "plan" a "subscription_plan"
                    'plan': result[5] or 'free',  # También mantener plan original
                    'credits': result[6] or 100,
                    'auth_provider': result[7] or 'manual',
                    'google_id': result[8],
                    'is_active': result[9] if result[9] is not None else True,
                    'is_admin': result[10] if result[10] is not None else False,
                    'created_at': result[11],
                    'updated_at': result[12]
                }
            return None
    except Exception as e:
        print(f"❌ Error getting user by ID: {e}")
        return None

def get_user_by_email(email):
    """Obtiene usuario por email - CORREGIDO para tu esquema EXACTO"""
    try:
        with engine.connect() as conn:
            result = conn.execute(
                text("""
                    SELECT id, email, password_hash, first_name, last_name, 
                           plan, credits, auth_provider, google_id, 
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
                    'subscription_plan': result[5] or 'free',  # Mapear "plan" a "subscription_plan"
                    'plan': result[5] or 'free',  # También mantener plan original
                    'credits': result[6] or 100,
                    'auth_provider': result[7] or 'manual',
                    'google_id': result[8],
                    'is_active': result[9] if result[9] is not None else True,
                    'is_admin': result[10] if result[10] is not None else False,
                    'created_at': result[11],
                    'updated_at': result[12]
                }
            return None
    except Exception as e:
        print(f"❌ Error getting user by email: {e}")
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
    """Crea nuevo usuario"""
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
    """Valida que la contraseña cumpla con los requisitos"""
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
    """Cobra créditos al usuario - PERFECTO para tu esquema"""
    try:
        print(f"💸 Cobrando {amount} créditos al usuario {user_id}")
        
        with engine.connect() as conn:
            # Verificar créditos actuales
            current_result = conn.execute(
                text("SELECT credits FROM users WHERE id = :user_id"),
                {"user_id": user_id}
            ).fetchone()
            
            if not current_result:
                print(f"❌ Usuario {user_id} no encontrado")
                return None
            
            current_credits = current_result[0] or 0
            print(f"💰 Créditos actuales: {current_credits}")
            
            if current_credits < amount:
                print(f"❌ Créditos insuficientes: {current_credits} < {amount}")
                return None
            
            # Hacer el cobro - updated_at existe en tu tabla
            result = conn.execute(
                text("""
                    UPDATE users 
                    SET credits = credits - :amount,
                        updated_at = NOW()
                    WHERE id = :user_id
                    RETURNING credits
                """),
                {"user_id": user_id, "amount": amount}
            ).fetchone()
            
            if result:
                new_credits = result[0]
                conn.commit()
                
                print(f"✅ Cobro exitoso: {current_credits} -> {new_credits}")
                
                # Log transaction - tu tabla credit_transactions existe
                try:
                    log_credit_transaction(user_id, -amount, 'charge', 'Bot usage')
                except Exception as log_error:
                    print(f"⚠️ Error logging transaction: {log_error}")
                
                return new_credits
            else:
                print(f"❌ Error en UPDATE de créditos")
                return None
                
    except Exception as e:
        print(f"❌ Error charging credits: {e}")
        import traceback
        traceback.print_exc()
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
    """Registra transacción de créditos - PERFECTO para tu esquema"""
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

def verify_google_access_token(access_token):
    """Verifica Google access token"""
    try:
        print(f"🔍 Verifying Google access token...")
        
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

# ==============================================================================
#           NEURAL MEMORY SYSTEM
# ==============================================================================

def init_neural_memory(user_id):
    """Inicializa memoria neuronal para usuario"""
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
    """
    Guarda interacción en memoria neuronal - OPTIMIZADO para tu esquema
    Todas las columnas existen en tu DB, así que esta función es PERFECTA
    """
    try:
        interaction_id = str(uuid.uuid4())
        
        with engine.connect() as conn:
            conn.execute(
                text("""
                    INSERT INTO neural_interactions (
                        id, user_id, bot_used, user_input, bot_output, 
                        credits_charged, context_data, session_id, project_id, created_at
                    ) VALUES (
                        :id, :user_id, :bot_used, :user_input, :bot_output,
                        :credits_charged, :context_data, :session_id, :project_id, NOW()
                    )
                """),
                {
                    "id": interaction_id,
                    "user_id": user_id,
                    "bot_used": interaction_data.get('bot', 'unknown'),
                    "user_input": interaction_data.get('input', ''),
                    "bot_output": interaction_data.get('response', ''),
                    "credits_charged": interaction_data.get('credits_used', 0),
                    "context_data": json.dumps(interaction_data.get('context', {})),
                    "session_id": interaction_data.get('session_id'),
                    "project_id": interaction_data.get('project_id')
                }
            )
            conn.commit()
            
            # Si es la primera interacción de la sesión, generar título
            session_id = interaction_data.get('session_id')
            if session_id:
                check_and_generate_session_title(session_id, user_id, interaction_data)
            
            print(f"✅ Interaction saved: {interaction_id}")
    
    except Exception as e:
        print(f"❌ Error saving interaction: {e}")
        import traceback
        traceback.print_exc()


def check_and_generate_session_title(session_id, user_id, interaction_data):
    """Genera título para la sesión si es la primera interacción"""
    try:
        with engine.connect() as conn:
            # Verificar si ya existe título para esta sesión
            existing_title = conn.execute(
                text("""
                    SELECT session_title FROM neural_interactions 
                    WHERE session_id = :session_id AND user_id = :user_id 
                    AND session_title IS NOT NULL
                    LIMIT 1
                """),
                {"session_id": session_id, "user_id": user_id}
            ).fetchone()
            
            if existing_title:
                return  # Ya tiene título
            
            # Generar título con Gemini
            user_input = interaction_data.get('input', '')
            bot_response = interaction_data.get('response', '')
            
            title = generate_chat_title_with_gemini(user_input, bot_response)
            
            # Actualizar la interacción con el título
            conn.execute(
                text("""
                    UPDATE neural_interactions 
                    SET session_title = :title 
                    WHERE session_id = :session_id AND user_id = :user_id
                """),
                {"title": title, "session_id": session_id, "user_id": user_id}
            )
            conn.commit()
            
            print(f"✅ Session title generated: {title}")
            
    except Exception as e:
        print(f"❌ Error generating session title: {e}")

def generate_chat_title_with_gemini(user_input, bot_response):
    """Genera título inteligente usando Gemini"""
    try:
        title_prompt = f"""
        Genera un título corto y descriptivo (máximo 5 palabras) para esta conversación.
        El título debe capturar la esencia de lo que el usuario está preguntando o trabajando.
        
        Usuario preguntó: {user_input[:200]}
        Asistente respondió sobre: {bot_response[:200]}
        
        Ejemplos de buenos títulos:
        - "Pitch Deck para FinTech"
        - "Buscar Inversores Seed"
        - "Marketing Plan SaaS"
        - "Análisis Competencia EdTech"
        - "Modelo Financiero B2B"
        
        Responde SOLO con el título, sin comillas ni explicaciones:
        """
        
        model = genai.GenerativeModel(MODEL_NAME)
        response = model.generate_content(
            title_prompt,
            generation_config={
                "temperature": 0.3,
                "max_output_tokens": 20,
            }
        )
        
        title = response.text.strip()
        
        # Limpiar el título
        title = title.replace('"', '').replace("'", '').strip()
        
        # Validar longitud
        if len(title) > 50:
            title = title[:47] + "..."
        
        return title if title else "Nueva Conversación"
        
    except Exception as e:
        print(f"❌ Error generating title: {e}")
        return "Nueva Conversación"

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

def extract_and_update_project_memory(user_id, project_id, user_input, bot_response):
    """
    Extrae información clave del chat y actualiza la memoria del proyecto
    """
    try:
        # Obtener memoria actual del proyecto
        with engine.connect() as conn:
            result = conn.execute(
                text("""
                    SELECT kpi_data FROM projects 
                    WHERE id = :project_id AND user_id = :user_id
                """),
                {"project_id": project_id, "user_id": user_id}
            ).fetchone()
            
            if not result:
                return False
            
            current_memory = json.loads(result[0]) if result[0] else {}
        
        # Extraer información del input del usuario
        extracted_info = extract_business_info(user_input + " " + bot_response)
        
        # Actualizar memoria con nueva información
        updated_memory = merge_memory_data(current_memory, extracted_info)
        
        # Guardar memoria actualizada
        with engine.connect() as conn:
            conn.execute(
                text("""
                    UPDATE projects 
                    SET kpi_data = :memory_data, updated_at = NOW()
                    WHERE id = :project_id AND user_id = :user_id
                """),
                {
                    "memory_data": json.dumps(updated_memory),
                    "project_id": project_id,
                    "user_id": user_id
                }
            )
            conn.commit()
        
        print(f"✅ Project memory updated for project {project_id}")
        return True
        
    except Exception as e:
        print(f"❌ Error updating project memory: {e}")
        return False

def extract_business_info(text):
    """
    Extrae información de negocio del texto usando Gemini
    """
    try:
        extraction_prompt = f"""
        Analiza el siguiente texto y extrae SOLO la información de negocio específica que mencione el usuario.
        NO inventes información que no esté explícitamente mencionada.
        
        Texto: {text}
        
        Devuelve SOLO un JSON con esta estructura (solo incluye campos que tengan información real):
        {{
            "startup_name": "nombre si se menciona",
            "industry": "industria específica si se menciona", 
            "stage": "etapa si se menciona (idea, mvp, seed, series_a, etc)",
            "business_model": "modelo de negocio si se describe",
            "target_market": "mercado objetivo si se especifica",
            "problem_solving": "problema que resuelve si se explica",
            "revenue_model": "como genera dinero si se menciona",
            "team_size": "tamaño del equipo si se menciona",
            "location": "ubicación si se especifica",
            "funding_raised": "dinero levantado si se menciona",
            "funding_needed": "dinero que necesita si se menciona",
            "competitors": ["competidores si se mencionan"],
            "key_metrics": "métricas clave si se mencionan",
            "current_challenges": ["retos actuales si se mencionan"],
            "business_type": "real_startup, side_project, o idea_stage"
        }}
        
        Si no hay información específica, devuelve {{}}.
        """
        
        model = genai.GenerativeModel(MODEL_NAME)
        response = model.generate_content(
            extraction_prompt,
            generation_config={
                "temperature": 0.1,
                "max_output_tokens": 1000,
            }
        )
        
        # Extraer JSON de la respuesta
        response_text = response.text.strip()
        if response_text.startswith('```json'):
            response_text = response_text[7:-3]
        elif response_text.startswith('```'):
            response_text = response_text[3:-3]
        
        try:
            extracted_data = json.loads(response_text)
            return extracted_data
        except json.JSONDecodeError:
            print(f"⚠️ Could not parse JSON from Gemini: {response_text}")
            return {}
        
    except Exception as e:
        print(f"❌ Error extracting business info: {e}")
        return {}

def merge_memory_data(current_memory, new_info):
    """
    Combina memoria actual con nueva información inteligentemente
    """
    try:
        # Inicializar estructura si no existe
        if not current_memory:
            current_memory = {
                "business_context": {},
                "chat_history_summary": [],
                "investor_preferences": {},
                "document_history": [],
                "last_updated": datetime.now().isoformat()
            }
        
        # Actualizar contexto de negocio
        business_context = current_memory.get("business_context", {})
        
        for key, value in new_info.items():
            if value and value != "":  # Solo actualizar si hay valor real
                if key == "competitors" and isinstance(value, list):
                    # Combinar listas de competidores
                    existing = business_context.get(key, [])
                    business_context[key] = list(set(existing + value))
                elif key == "current_challenges" and isinstance(value, list):
                    # Combinar listas de retos
                    existing = business_context.get(key, [])
                    business_context[key] = list(set(existing + value))
                else:
                    # Actualizar valor simple
                    business_context[key] = value
        
        current_memory["business_context"] = business_context
        current_memory["last_updated"] = datetime.now().isoformat()
        
        return current_memory
        
    except Exception as e:
        print(f"❌ Error merging memory data: {e}")
        return current_memory or {}

def get_enhanced_context_for_chat(user, session_id, project_id, data):
    """Obtiene contexto mejorado para el chat - VERSIÓN CORRECTA"""
    try:
        # Obtener contexto del proyecto
        project_context = get_project_context_for_chat(user['id'], project_id)
        
        # Contexto base
        enhanced_context = {
            'user_id': user['id'],
            'user_plan': user.get('plan', 'free'),  # usar 'plan' no 'subscription_plan'
            'session_id': session_id,
            'project_id': project_id,
            'user_credits_before': get_user_credits(user['id']),
            'user_language': detect_user_language(data.get('message', '')),  # DETECTAR IDIOMA
            **data.get('context', {}),
            **project_context
        }
        
        return enhanced_context
    except Exception as e:
        print(f"❌ Error getting enhanced context: {e}")
        return {
            'user_id': user['id'],
            'user_plan': user.get('plan', 'free'),
            'session_id': session_id,
            'project_id': project_id
        }
        
def get_project_context_for_chat(user_id, project_id):
    """
    Obtiene el contexto completo del proyecto para el chat - OPTIMIZADO
    """
    try:
        with engine.connect() as conn:
            # Obtener información del proyecto
            project_result = conn.execute(
                text("""
                    SELECT project_name, project_description, kpi_data, status, created_at
                    FROM projects 
                    WHERE id = :project_id AND user_id = :user_id
                """),
                {"project_id": project_id, "user_id": user_id}
            ).fetchone()
            
            if not project_result:
                return {}
            
            # Obtener últimas interacciones del proyecto
            recent_chats = conn.execute(
                text("""
                    SELECT user_input, bot_output, created_at 
                    FROM neural_interactions 
                    WHERE user_id = :user_id AND project_id = :project_id 
                    ORDER BY created_at DESC 
                    LIMIT 10
                """),
                {"user_id": user_id, "project_id": project_id}
            ).fetchall()
            
            # Obtener documentos del proyecto usando el extract function que ya existe en tu DB
            project_docs = conn.execute(
                text("""
                    SELECT document_type, title, created_at 
                    FROM generated_documents 
                    WHERE user_id = :user_id 
                    AND extract_project_id_from_metadata(metadata) = :project_id
                    ORDER BY created_at DESC
                """),
                {"user_id": user_id, "project_id": project_id}
            ).fetchall()
        
        # Procesar memoria del proyecto
        project_memory = json.loads(project_result[2]) if project_result[2] else {}
        business_context = project_memory.get("business_context", {})
        
        # Crear resumen de chats recientes
        recent_context = []
        for chat in recent_chats[:5]:  # Últimos 5 chats
            recent_context.append({
                "user_said": chat[0][:100] + "..." if len(chat[0]) > 100 else chat[0],
                "assistant_responded": chat[1][:100] + "..." if len(chat[1]) > 100 else chat[1],
                "when": chat[2].strftime("%Y-%m-%d")
            })
        
        # Crear lista de documentos
        documents_created = [
            {
                "type": doc[0],
                "title": doc[1],
                "created": doc[2].strftime("%Y-%m-%d")
            }
            for doc in project_docs
        ]
        
        return {
            "project_name": project_result[0],
            "project_description": project_result[1],
            "project_status": project_result[3],
            "project_age_days": (datetime.now() - project_result[4]).days,
            "business_context": business_context,
            "recent_conversation_context": recent_context,
            "documents_created": documents_created,
            "total_interactions": len(recent_chats),
            "context_summary": generate_context_summary(business_context, recent_context)
        }
        
    except Exception as e:
        print(f"❌ Error getting project context: {e}")
        return {}

def generate_context_summary(business_context, recent_chats):
    """Genera un resumen del contexto para incluir en prompts"""
    try:
        summary_parts = []
        
        # Información del negocio
        if business_context.get("startup_name"):
            summary_parts.append(f"Startup: {business_context['startup_name']}")
        
        if business_context.get("industry"):
            summary_parts.append(f"Industria: {business_context['industry']}")
        
        if business_context.get("stage"):
            summary_parts.append(f"Etapa: {business_context['stage']}")
        
        if business_context.get("business_type"):
            summary_parts.append(f"Tipo: {business_context['business_type']}")
        
        if business_context.get("problem_solving"):
            summary_parts.append(f"Problema que resuelve: {business_context['problem_solving']}")
        
        # Contexto reciente
        if recent_chats:
            summary_parts.append(f"Últimas conversaciones: {len(recent_chats)} interacciones recientes")
        
        return " | ".join(summary_parts) if summary_parts else "Nuevo proyecto sin contexto previo"
        
    except Exception as e:
        print(f"❌ Error generating context summary: {e}")
        return "Error generando resumen de contexto"

def get_enhanced_context_for_chat(user, session_id, project_id, data):
    """Obtiene contexto mejorado para el chat"""
    
    # Obtener contexto del proyecto
    project_context = get_project_context_for_chat(user['id'], project_id)
    
    # Contexto base
    enhanced_context = {
        'user_id': user['id'],
        'user_plan': user.get('subscription_plan', user.get('plan', 'free')),  # Compatibilidad
        'session_id': session_id,
        'project_id': project_id,
        'user_credits_before': get_user_credits(user['id']),
        **data.get('context', {}),
        **project_context
    }
    
    return enhanced_context
        
# ==============================================================================
#           BOT SYSTEM
# ==============================================================================

class BotManager:
    def process_user_request(self, user_input, user_context, user_id):
        """Procesa request del usuario con tracking correcto de créditos"""
        try:
            # 1. VERIFICAR CRÉDITOS ACTUALES
            credits_before = get_user_credits(user_id)
            required_credits = CREDIT_COSTS.get('basic_bot', 5)
            
            print(f"🤖 Bot procesando:")
            print(f"   - Usuario: {user_id}")
            print(f"   - Créditos antes: {credits_before}")
            print(f"   - Créditos requeridos: {required_credits}")
            print(f"   - Idioma detectado: {user_context.get('user_language', 'en')}")
            
            if credits_before < required_credits:
                return {
                    'error': 'Insufficient credits',
                    'required': required_credits,
                    'available': credits_before
                }
            
            # 2. GENERAR RESPUESTA CON GEMINI
            prompt = self._build_smart_prompt(user_input, user_context)
            
            model = genai.GenerativeModel(MODEL_NAME)
            ai_response = model.generate_content(
                prompt,
                generation_config={
                    "temperature": 0.7,
                    "top_p": 0.95,
                    "top_k": 40,
                    "max_output_tokens": 2000,
                }
            )
            
            # 3. COBRAR CRÉDITOS
            print(f"💳 Cobrando {required_credits} créditos...")
            credits_after_charge = charge_credits(user_id, required_credits)
            
            if credits_after_charge is None:
                return {'error': 'Could not charge credits'}
            
            print(f"✅ Créditos después del cobro: {credits_after_charge}")
            
            # 4. GUARDAR INTERACCIÓN
            save_neural_interaction(user_id, {
                'bot': 'interactive_mentor',
                'input': user_input,
                'response': ai_response.text,
                'credits_used': required_credits,
                'context': user_context,
                'session_id': user_context.get('session_id'),
                'project_id': user_context.get('project_id')
            })
            
            # 5. RETORNAR RESPUESTA
            return {
                'bot': 'interactive_mentor',
                'response': ai_response.text,
                'credits_charged_by_bot': required_credits,
                'processing_success': True
            }
            
        except Exception as e:
            print(f"❌ Error in bot processing: {e}")
            import traceback
            traceback.print_exc()
            return {'error': f'Bot error: {str(e)}'}



def _build_smart_prompt(self, user_input, user_context):
        """Construye prompt inteligente basado en contexto"""
        # Obtener información del contexto
        business_context = user_context.get('business_context', {})
        user_plan = user_context.get('user_plan', 'free')
        user_language = user_context.get('user_language', 'en')
        recent_conversations = user_context.get('recent_conversation_context', [])
        
        # DETERMINAR IDIOMA PARA EL PROMPT
        language_instruction = {
            'es': "Responde SIEMPRE en español.",
            'en': "Respond ALWAYS in English.",
        }.get(user_language, "Respond in the same language as the user.")
        
        prompt = f"""
        You are an expert startup mentor with 50+ successful exits.
        
        {language_instruction}
        
        PROJECT CONTEXT:
        - Industry: {business_context.get('industry', 'Not specified')}
        - Stage: {business_context.get('stage', 'Initial')}
        - Type: {business_context.get('business_type', 'Project')}
        - Problem solving: {business_context.get('problem_solving', 'Not defined')}
        - User plan: {user_plan}
        
        RECENT CONVERSATIONS:
        {self._format_recent_conversations(recent_conversations)}
        
        DOCUMENTS CREATED:
        {user_context.get('documents_created', [])}
        
        USER ASKS: {user_input}
        
        INSTRUCTIONS:
        - {language_instruction}
        - Respond as an experienced mentor, not as AI
        - Give practical and actionable advice
        - If they ask for documents (pitch deck, business plan), offer to generate them
        - Be honest about entrepreneurship challenges
        - Use real examples when appropriate
        - Adjust your response to their level (idea vs real startup)
        - Length: 100-800 words depending on complexity
        
        If plan is 'free' and they need advanced features, naturally mention upgrade benefits.
        
        Respond directly, practically, and helpfully:
        """
        
        return prompt


 def _format_recent_conversations(self, conversations):
        """Formatea conversaciones recientes para contexto"""
        if not conversations:
            return "No previous conversations"
        
        formatted = []
        for conv in conversations[-3:]:  # Últimas 3
            formatted.append(f"- User said: {conv.get('user_said', '')}")
            formatted.append(f"- Assistant responded: {conv.get('assistant_responded', '')}")
        
        return '\n'.join(formatted)


# Actualizar la instancia global (ESTA LÍNEA YA EXISTE, NO LA CAMBIES)
bot_manager = BotManager()
# ==============================================================================
#           ROUTES
# ==============================================================================

@app.route('/')
def home():
    """Home endpoint"""
    return jsonify({
        'status': 'online',
        'version': '2.0.0',
        'message': '🚀 0Bullshit Backend API - CORS ARREGLADO DEFINITIVAMENTE! 🎉',
        'auth_methods': ['manual', 'google'],
        'database_connected': engine is not None,
        'google_auth_enabled': GOOGLE_CLIENT_ID is not None,
        'cors_status': '✅ CORS KILLER ACTIVADO',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/cors-test', methods=['GET', 'POST', 'OPTIONS'])
def cors_test():
    """Endpoint para testear que CORS funciona - CORS KILLER TEST"""
    return jsonify({
        'message': '🎉 CORS está funcionando PERFECTAMENTE!',
        'method': request.method,
        'origin': request.headers.get('Origin', 'No origin'),
        'user_agent': request.headers.get('User-Agent', 'No user agent')[:50] + '...',
        'headers_received': dict(request.headers),
        'timestamp': datetime.now().isoformat(),
        'cors_status': '✅ CORS KILLER FUNCIONANDO',
        'backend_status': 'ONLINE',
        'database_status': 'CONNECTED' if engine else 'DISCONNECTED'
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
            'environment': 'production' if 'render.com' in os.environ.get('RENDER_EXTERNAL_URL', '') else 'development',
            'cors_status': '✅ CORS KILLER ACTIVE'
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
            'timestamp': datetime.now().isoformat(),
            'cors_working': True
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/auth/register', methods=['POST'])
def register():
    """Registro de usuario"""
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
    """Login de usuario"""
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
    """Google auth endpoint"""
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

# ==============================================================================
#           CHAT ENDPOINTS WITH SESSION MANAGEMENT
# ==============================================================================

@app.route('/chat/new', methods=['POST'])
@require_auth
def create_new_chat(user):
    """
    Crea una nueva conversación asociada a un proyecto
    VERSIÓN ROBUSTA - Maneja JSON malformado del frontend
    """
    try:
        # MANEJO ROBUSTO DEL JSON
        try:
            data = request.get_json(force=True) or {}
        except Exception as json_error:
            print(f"⚠️ JSON parse error: {json_error}")
            print(f"📝 Raw request data: {request.data}")
            print(f"📋 Content-Type: {request.content_type}")
            
            # Si no hay JSON válido, usar valores por defecto
            data = {}
        
        project_id = data.get('project_id')
        
        print(f"🔍 Creating chat for user: {user['id']}")
        print(f"📝 Project ID provided: {project_id}")
        print(f"📊 Request data: {data}")
        
        # Si no hay project_id, buscar o crear uno
        if not project_id:
            print("🔍 No project_id provided, looking for user's projects...")
            
            with engine.connect() as conn:
                # Buscar proyectos existentes del usuario
                project_result = conn.execute(
                    text("""
                        SELECT id FROM projects 
                        WHERE user_id = :user_id 
                        ORDER BY created_at DESC 
                        LIMIT 1
                    """),
                    {"user_id": user['id']}
                ).fetchone()
                
                if project_result:
                    project_id = str(project_result[0])
                    print(f"✅ Using existing project: {project_id}")
                else:
                    # Crear proyecto por defecto
                    project_id = str(uuid.uuid4())
                    print(f"📝 Creating default project: {project_id}")
                    
                    # ✅ INSERT CORREGIDO CON updated_at
                    conn.execute(
                        text("""
                            INSERT INTO projects (
                                id, user_id, project_name, project_description, 
                                kpi_data, status, created_at, updated_at
                            ) VALUES (
                                :id, :user_id, :project_name, :project_description, 
                                :kpi_data, :status, NOW(), NOW()
                            )
                        """),
                        {
                            "id": project_id,
                            "user_id": user['id'],
                            "project_name": "Mi Proyecto Principal",
                            "project_description": "Proyecto creado automáticamente para el chat",
                            "kpi_data": json.dumps({
                                "created_automatically": True,
                                "creation_source": "chat_new_endpoint",
                                "created_at": datetime.now().isoformat()
                            }),
                            "status": "ONBOARDING"
                        }
                    )
                    conn.commit()
                    print(f"✅ Default project created successfully: {project_id}")
        else:
            # Verificar que el proyecto existe y pertenece al usuario
            with engine.connect() as conn:
                project_check = conn.execute(
                    text("""
                        SELECT id, project_name FROM projects 
                        WHERE id = :project_id AND user_id = :user_id
                    """),
                    {"project_id": project_id, "user_id": user['id']}
                ).fetchone()
                
                if not project_check:
                    return jsonify({
                        'error': 'Project not found or access denied',
                        'provided_project_id': project_id,
                        'user_id': user['id'],
                        'suggestion': 'Create a new chat without project_id to auto-create a project'
                    }), 404
                else:
                    print(f"✅ Project verified: {project_check[1]} ({project_id})")
        
        # Generar session_id único para el chat
        session_id = str(uuid.uuid4())
        
        print(f"🎉 New chat session created successfully:")
        print(f"   - User: {user['id']}")
        print(f"   - Project: {project_id}")
        print(f"   - Session: {session_id}")
        
        return jsonify({
            'success': True,
            'session_id': session_id,
            'project_id': project_id,
            'message': 'New chat session created successfully',
            'user_id': user['id'],
            'timestamp': datetime.now().isoformat(),
            'debug_info': {
                'received_data': data,
                'content_type': request.content_type,
                'has_json': bool(data)
            }
        })
        
    except Exception as e:
        print(f"❌ Error creating new chat: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'error': 'Could not create new chat session',
            'details': str(e),
            'timestamp': datetime.now().isoformat(),
            'debug_info': {
                'raw_data': str(request.data),
                'content_type': request.content_type,
                'method': request.method
            }
        }), 500

@app.route('/chat/bot', methods=['POST'])
@require_auth
def chat_with_bot(user):
    """
    Procesa mensaje del usuario y retorna respuesta del bot
    VERSIÓN MEJORADA - Compatible con la nueva estructura
    """
    try:
        data = request.get_json()
        
        # VALIDACIÓN BÁSICA
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        if not data.get('message'):
            return jsonify({'error': 'Message is required'}), 400
        
        # PROJECT_ID Y SESSION_ID son requeridos ahora
        project_id = data.get('project_id')
        session_id = data.get('session_id')
        
        if not project_id:
            return jsonify({
                'error': 'project_id is required',
                'suggestion': 'Use /chat/new to create a new chat session first'
            }), 400
        
        if not session_id:
            return jsonify({
                'error': 'session_id is required',
                'suggestion': 'Use /chat/new to create a new chat session first'
            }), 400
        
        # VERIFICAR que el proyecto pertenece al usuario
        with engine.connect() as conn:
            project_result = conn.execute(
                text("""
                    SELECT id, project_name, project_description, kpi_data 
                    FROM projects 
                    WHERE id = :project_id AND user_id = :user_id
                """),
                {"project_id": project_id, "user_id": user['id']}
            ).fetchone()
            
            if not project_result:
                return jsonify({
                    'error': 'Project not found or access denied',
                    'project_id': project_id,
                    'user_id': user['id']
                }), 404
        
        # EXTRAER CONTEXTO DEL PROYECTO
        project_context = {
            'project_id': project_id,
            'project_name': project_result[1] if project_result[1] else 'Mi Proyecto',
            'project_description': project_result[2] if project_result[2] else '',
            'project_data': project_result[3] if isinstance(project_result[3], dict) else (json.loads(project_result[3]) if project_result[3] else {})
        }
        
        # VERIFICAR CRÉDITOS
        user_credits_before = get_user_credits(user['id'])
        credits_required = CREDIT_COSTS.get('basic_bot', 5)
        
        if user_credits_before < credits_required:
            return jsonify({
                'error': 'Insufficient credits',
                'required': credits_required,
                'available': user_credits_before,
                'upgrade_needed': True
            }), 402
            
        # PREPARAR CONTEXTO COMPLETO

@app.route('/chat/history', methods=['GET'])
@require_auth
def get_chat_history(user):
    """Obtiene historial de conversaciones agrupadas por sesión"""
    try:
        with engine.connect() as conn:
            # Obtener conversaciones agrupadas por session_id
            result = conn.execute(text("""
                SELECT 
                    COALESCE(session_id, id::text) as conversation_id,
                    MIN(created_at) as started_at,
                    MAX(created_at) as last_message_at,
                    COUNT(*) as message_count,
                    MAX(user_input) as last_message,
                    MAX(bot_used) as last_bot
                FROM neural_interactions 
                WHERE user_id = :user_id 
                GROUP BY COALESCE(session_id, id::text)
                ORDER BY MAX(created_at) DESC
                LIMIT 20
            """), {"user_id": user['id']}).fetchall()
            
            conversations = []
            for row in result:
                conversations.append({
                    'conversation_id': row[0],
                    'started_at': row[1].isoformat(),
                    'last_message_at': row[2].isoformat(),
                    'message_count': row[3],
                    'last_message': row[4][:100] + '...' if len(row[4]) > 100 else row[4],
                    'last_bot': row[5]
                })
        
        return jsonify({
            'success': True,
            'conversations': conversations
        })
        
    except Exception as e:
        print(f"Error getting chat history: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/chat/conversation/<conversation_id>', methods=['GET'])
@require_auth
def get_conversation_messages(user, conversation_id):
    """Obtiene todos los mensajes de una conversación específica"""
    try:
        with engine.connect() as conn:
            result = conn.execute(text("""
                SELECT id, bot_used, user_input, bot_output, credits_charged, 
                       context_data, created_at
                FROM neural_interactions
                WHERE user_id = :user_id 
                AND (session_id = :conversation_id OR id::text = :conversation_id)
                ORDER BY created_at ASC
            """), {
                "user_id": user['id'],
                "conversation_id": conversation_id
            }).fetchall()
            
            messages = []
            for row in result:
                messages.append({
                    'id': str(row[0]),
                    'bot_used': row[1],
                    'user_input': row[2],
                    'bot_output': row[3],
                    'credits_charged': row[4],
                    'context_data': json.loads(row[5]) if row[5] else {},
                    'created_at': row[6].isoformat()
                })
        
        return jsonify({
            'success': True,
            'conversation_id': conversation_id,
            'messages': messages
        })
        
    except Exception as e:
        print(f"Error getting conversation: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/chat/stats', methods=['GET'])
@require_auth
def get_chat_stats(user):
    """Get user's chat statistics"""
    try:
        with engine.connect() as conn:
            # Total interactions
            total_result = conn.execute(text("""
                SELECT COUNT(*) FROM neural_interactions WHERE user_id = :user_id
            """), {"user_id": user['id']}).scalar()
            
            # Bot usage stats
            bot_stats_result = conn.execute(text("""
                SELECT bot_used, COUNT(*) as usage_count, SUM(credits_charged) as total_credits
                FROM neural_interactions 
                WHERE user_id = :user_id 
                GROUP BY bot_used 
                ORDER BY usage_count DESC
            """), {"user_id": user['id']}).fetchall()
            
            # Recent activity (last 7 days)
            recent_activity = conn.execute(text("""
                SELECT DATE(created_at) as date, COUNT(*) as count
                FROM neural_interactions 
                WHERE user_id = :user_id AND created_at > NOW() - INTERVAL '7 days'
                GROUP BY DATE(created_at)
                ORDER BY date DESC
            """), {"user_id": user['id']}).fetchall()
            
            bot_stats = []
            for row in bot_stats_result:
                bot_stats.append({
                    'bot_name': row[0],
                    'usage_count': row[1],
                    'total_credits': row[2]
                })
            
            activity_data = []
            for row in recent_activity:
                activity_data.append({
                    'date': row[0].isoformat(),
                    'count': row[1]
                })
        
        return jsonify({
            'success': True,
            'total_interactions': total_result or 0,
            'bot_usage_stats': bot_stats,
            'recent_activity': activity_data
        })
        
    except Exception as e:
        print(f"Error getting chat stats: {e}")
        return jsonify({'error': 'Failed to get chat statistics'}), 500

# ==============================================================================
#           PROJECT CONTEXT ENDPOINTS
# ==============================================================================

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
#           ADMIN ENDPOINTS
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

# ==============================================================================
#           ERROR HANDLERS
# ==============================================================================

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({'error': 'Method not allowed'}), 405

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

# ENDPOINT /projects ARREGLADO PARA TU ESQUEMA EXACTO

@app.route('/projects', methods=['GET', 'POST'])
@require_auth
def handle_projects(user):
    """Handle projects endpoint - ESQUEMA CORRECTO"""
    try:
        if request.method == 'GET':
            with engine.connect() as conn:
                result = conn.execute(
                    text("""
                        SELECT id, user_id, project_name, project_description, kpi_data, status, created_at
                        FROM projects 
                        WHERE user_id = :user_id
                        ORDER BY created_at DESC
                    """),
                    {"user_id": user['id']}
                ).fetchall()
                
                projects = []
                for row in result:
                    try:
                        kpi_data = json.loads(row[4]) if row[4] else {}
                    except:
                        kpi_data = {}
                    
                    projects.append({
                        'id': str(row[0]),
                        'user_id': str(row[1]),
                        'project_name': row[2],
                        'project_description': row[3],
                        'kpi_data': kpi_data,
                        'status': row[5],
                        'created_at': row[6].isoformat() if row[6] else None
                    })
            
            return jsonify({
                'success': True,
                'projects': projects,
                'count': len(projects)
            })
        
        elif request.method == 'POST':
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No data provided'}), 400
            
            project_id = str(uuid.uuid4())
            project_name = data.get('name', 'Untitled Project')
            project_description = data.get('description', '')
            
            project_data = {
                'name': data.get('name', ''),
                'description': data.get('description', ''),
                'industry': data.get('industry', ''),
                'stage': data.get('stage', ''),
                'location': data.get('location', ''),
                'website': data.get('website', ''),
                'created_by': user['email']
            }
            
            with engine.connect() as conn:
                # ✅ INSERT CORREGIDO - Incluye updated_at
                conn.execute(
                    text("""
                        INSERT INTO projects (
                            id, user_id, project_name, project_description, kpi_data, status, created_at, updated_at
                        ) VALUES (
                            :id, :user_id, :project_name, :project_description, :kpi_data, :status, NOW(), NOW()
                        )
                    """),
                    {
                        "id": project_id,
                        "user_id": user['id'],
                        "project_name": project_name,
                        "project_description": project_description,
                        "kpi_data": json.dumps(project_data),
                        "status": "ONBOARDING"
                    }
                )
                conn.commit()
                print(f"✅ Project created successfully: {project_id}")
            
            return jsonify({
                'success': True,
                'message': 'Project created successfully',
                'project_id': project_id
            })
            
    except Exception as e:
        print(f"❌ Error in projects endpoint: {e}")
        return jsonify({'error': f'Database error: {str(e)}'}), 500


# ==============================================================================
#           NUEVOS ENDPOINTS QUE FALTAN
# ==============================================================================

# 1. ✅ ENDPOINT: /chat/recent - Obtener chats recientes
@app.route('/chat/recent', methods=['GET'])
@require_auth
def get_recent_chats_with_titles(user):
    """Obtiene chats recientes con títulos - OPTIMIZADO para tu esquema exacto"""
    try:
        limit = min(int(request.args.get('limit', 20)), 50)
        project_id = request.args.get('project_id')
        
        base_query = """
            SELECT 
                COALESCE(ni.session_id::text, ni.id::text) as session_id,
                ni.project_id,
                p.project_name,
                MIN(ni.created_at) as started_at,
                MAX(ni.created_at) as last_message_at,
                COUNT(*) as message_count,
                (array_agg(ni.user_input ORDER BY ni.created_at ASC))[1] as first_message,
                (array_agg(ni.user_input ORDER BY ni.created_at DESC))[1] as last_message_preview,
                (array_agg(ni.bot_used ORDER BY ni.created_at DESC))[1] as last_bot_used,
                MAX(ni.session_title) as session_title
            FROM neural_interactions ni
            LEFT JOIN projects p ON ni.project_id = p.id
            WHERE ni.user_id = :user_id
        """
        
        params = {"user_id": user['id'], "limit": limit}
        
        if project_id:
            base_query += " AND ni.project_id = :project_id"
            params["project_id"] = project_id
        
        base_query += """
            GROUP BY COALESCE(ni.session_id::text, ni.id::text), ni.project_id, p.project_name
            ORDER BY MAX(ni.created_at) DESC
            LIMIT :limit
        """
        
        with engine.connect() as conn:
            result = conn.execute(text(base_query), params).fetchall()
            
            chats = []
            for row in result:
                # Si no hay título, generarlo ahora
                display_title = row[9] if row[9] else generate_simple_title_from_message(row[6], row[7])
                
                chats.append({
                    'session_id': row[0],
                    'project_id': str(row[1]) if row[1] else None,
                    'project_name': row[2] or 'Sin proyecto',
                    'title': display_title,  # ¡TÍTULO AQUÍ!
                    'started_at': row[3].isoformat(),
                    'last_message_at': row[4].isoformat(),
                    'message_count': row[5],
                    'last_message_preview': (row[7][:60] + '...') if len(row[7] or '') > 60 else (row[7] or ''),
                    'last_bot_used': row[8] or 'unknown'
                })
        
        return jsonify({
            'success': True,
            'chats': chats,
            'total_count': len(chats),
            'filtered_by_project': project_id is not None
        })
        
    except Exception as e:
        print(f"❌ Error getting recent chats: {e}")
        return jsonify({'error': 'Could not get recent chats'}), 500

def generate_chat_title_from_messages(first_message, last_message):
    """Genera título a partir de mensajes si no existe"""
    try:
        if not first_message:
            return "Nueva Conversación"
        
        # Intentar generar título simple basado en palabras clave
        text = first_message.lower()
        
        if any(word in text for word in ['pitch', 'deck', 'presentacion']):
            return "Pitch Deck"
        elif any(word in text for word in ['inversor', 'investor', 'funding']):
            return "Búsqueda Inversores"
        elif any(word in text for word in ['marketing', 'contenido', 'seo']):
            return "Marketing Strategy"
        elif any(word in text for word in ['financi', 'modelo', 'revenue']):
            return "Modelo Financiero"
        elif any(word in text for word in ['plan', 'estrategia', 'negocio']):
            return "Plan de Negocio"
        elif any(word in text for word in ['competencia', 'mercado', 'analisis']):
            return "Análisis de Mercado"
        else:
            # Usar las primeras palabras
            words = first_message.split()[:3]
            return " ".join(words).title()
            
    except Exception as e:
        print(f"❌ Error generating simple title: {e}")
        return "Nueva Conversación"

# 2. ✅ ENDPOINT: /chat/messages/<session_id> - Obtener mensajes de un chat
@app.route('/chat/messages/<session_id>', methods=['GET'])
@require_auth
def get_chat_messages(user, session_id):
    """
    Obtiene todos los mensajes de una sesión/conversación específica
    
    REQUEST: GET /chat/messages/uuid-de-sesion
    """
    try:
        with engine.connect() as conn:
            result = conn.execute(text("""
                SELECT ni.id, ni.bot_used, ni.user_input, ni.bot_output, ni.credits_charged, 
       ni.context_data, ni.created_at, ni.project_id, p.project_name
                FROM neural_interactions ni
LEFT JOIN projects p ON ni.project_id = p.id
                WHERE user_id = :user_id 
                AND (session_id::text = :session_id OR id::text = :session_id)
                ORDER BY created_at ASC
            """), {
                "user_id": user['id'],
                "session_id": session_id
            }).fetchall()
            
            if not result:
                return jsonify({
                    'success': True,
                    'session_id': session_id,
                    'messages': [],
                    'total_messages': 0,
                    'message': 'No messages found for this session'
                })
            
            messages = []
            for row in result:
                try:
                    context_data = json.loads(row[5]) if row[5] else {}
                except:
                    context_data = {}
                
                messages.append({
                    'id': str(row[0]),
                    'user_message': row[2],
                    'bot_response': row[3],
                    'bot_used': row[1],
                    'credits_charged': row[4],
                    'timestamp': row[6].isoformat(),
                    'context': context_data
                })
        
        return jsonify({
            'success': True,
            'session_id': session_id,
            'messages': messages,
            'total_messages': len(messages)
        })
        
    except Exception as e:
        print(f"❌ Error getting chat messages: {e}")
        return jsonify({'error': 'Could not get chat messages'}), 500

# 3. ✅ ENDPOINT BONUS: /chat/delete/<session_id> - Eliminar conversación
@app.route('/chat/delete/<session_id>', methods=['DELETE'])
@require_auth
def delete_chat_session(user, session_id):
    """
    Elimina una conversación completa - SQL CORREGIDO
    """
    try:
        with engine.connect() as conn:
            # ✅ QUERY CORREGIDO - Sin referencia a tabla 'ni'
            count_result = conn.execute(text("""
                SELECT COUNT(*) FROM neural_interactions
                WHERE user_id = :user_id 
                AND (session_id::text = :session_id OR id::text = :session_id)
            """), {"user_id": user['id'], "session_id": session_id}).scalar()
            
            if count_result == 0:
                return jsonify({'error': 'Chat session not found'}), 404
            
            # ✅ DELETE CORREGIDO - Sin referencia a tabla 'ni'
            conn.execute(text("""
                DELETE FROM neural_interactions
                WHERE user_id = :user_id 
                AND (session_id::text = :session_id OR id::text = :session_id)
            """), {"user_id": user['id'], "session_id": session_id})
            
            conn.commit()
        
        return jsonify({
            'success': True,
            'message': 'Chat session deleted successfully',
            'deleted_messages': count_result
        })
        
    except Exception as e:
        print(f"❌ Error deleting chat session: {e}")
        return jsonify({'error': 'Could not delete chat session'}), 500


@app.route('/documents/generate', methods=['POST'])
@require_auth
def generate_document_with_bot(user):
    """Genera documento extenso usando bot específico"""
    try:
        data = request.get_json()
        
        if not data or not data.get('document_type') or not data.get('project_id'):
            return jsonify({'error': 'document_type and project_id are required'}), 400
        
        document_type = data['document_type']  # 'pitch_deck', 'business_plan', 'marketing_plan'
        project_id = data['project_id']
        user_requirements = data.get('requirements', '')
        
        # Verificar proyecto
        with engine.connect() as conn:
            project_result = conn.execute(
                text("SELECT * FROM projects WHERE id = :project_id AND user_id = :user_id"),
                {"project_id": project_id, "user_id": user['id']}
            ).fetchone()
            
            if not project_result:
                return jsonify({'error': 'Project not found'}), 404
        
        # Determinar bot y créditos requeridos
        bot_config = {
            'pitch_deck': {'bot': 'pitch_deck_master', 'credits': 100},
            'business_plan': {'bot': 'strategy_consultant', 'credits': 150},
            'marketing_plan': {'bot': 'content_machine', 'credits': 120},
            'financial_model': {'bot': 'financial_modeler', 'credits': 130}
        }
        
        if document_type not in bot_config:
            return jsonify({'error': 'Invalid document type'}), 400
        
        bot_id = bot_config[document_type]['bot']
        credits_required = bot_config[document_type]['credits']
        
        # Verificar créditos
        if not has_sufficient_credits(user['id'], credits_required):
            return jsonify({
                'error': 'Insufficient credits',
                'required': credits_required,
                'available': get_user_credits(user['id'])
            }), 402
        
        # Crear prompt especializado para documento extenso
        project_data = json.loads(project_result[4]) if project_result[4] else {}
        
        prompts = {
            'pitch_deck': f"""
            Eres el mejor creador de pitch decks del mundo. Crea un pitch deck COMPLETO y DETALLADO para esta startup.
            
            INFORMACIÓN DEL PROYECTO:
            - Nombre: {project_data.get('name', 'Mi Startup')}
            - Industria: {project_data.get('industry', 'Technology')}
            - Descripción: {project_data.get('description', '')}
            - Etapa: {project_data.get('stage', 'Seed')}
            
            REQUISITOS ESPECÍFICOS:
            {user_requirements}
            
            ESTRUCTURA REQUERIDA (crear cada sección en detalle):
            1. **COVER SLIDE**: Nombre, tagline, logo placeholder
            2. **PROBLEM**: Problema específico y dolor real
            3. **SOLUTION**: Solución única y diferenciada
            4. **MARKET SIZE**: TAM, SAM, SOM con números reales
            5. **PRODUCT**: Features clave y demostración
            6. **BUSINESS MODEL**: Cómo generas dinero
            7. **TRACTION**: Métricas y logros actuales
            8. **COMPETITION**: Análisis competitivo
            9. **MARKETING**: Go-to-market strategy
            10. **TEAM**: Fundadores y equipo clave
            11. **FINANCIALS**: Proyecciones 3-5 años
            12. **FUNDING**: Cantidad, uso de fondos, valoración
            13. **TIMELINE**: Roadmap y milestones
            14. **APPENDIX**: Información adicional
            
            FORMATO:
            - Cada slide con título H2
            - Contenido detallado y específico
            - Números y métricas concretas
            - Call-to-action en cada slide
            - Mínimo 2000 palabras total
            """,
            
            'business_plan': f"""
            Crea un BUSINESS PLAN COMPLETO y PROFESIONAL para esta startup.
            
            INFORMACIÓN DEL PROYECTO:
            - Nombre: {project_data.get('name', 'Mi Startup')}
            - Industria: {project_data.get('industry', 'Technology')}
            - Descripción: {project_data.get('description', '')}
            
            REQUISITOS:
            {user_requirements}
            
            ESTRUCTURA COMPLETA:
            
            ## 1. EXECUTIVE SUMMARY
            - Resumen ejecutivo de 2 páginas
            - Propuesta de valor única
            - Proyecciones financieras clave
            - Funding necesario
            
            ## 2. COMPANY DESCRIPTION
            - Historia y misión
            - Visión y valores
            - Estructura legal
            - Ubicación y operaciones
            
            ## 3. MARKET ANALYSIS
            - Análisis de industria
            - Target market segmentation
            - Market size (TAM, SAM, SOM)
            - Trends y oportunidades
            
            ## 4. COMPETITIVE ANALYSIS
            - Landscape competitivo
            - Direct vs indirect competitors
            - Análisis SWOT
            - Ventaja competitiva sostenible
            
            ## 5. PRODUCTS & SERVICES
            - Descripción detallada del producto
            - Features y beneficios
            - Roadmap de desarrollo
            - Intellectual property
            
            ## 6. MARKETING & SALES STRATEGY
            - Customer personas
            - Marketing mix (4Ps)
            - Sales funnel
            - Customer acquisition strategy
            - Pricing strategy
            
            ## 7. OPERATIONS PLAN
            - Operational workflow
            - Supply chain
            - Technology infrastructure
            - Quality control
            
            ## 8. MANAGEMENT TEAM
            - Team bios y experiencia
            - Organizational chart
            - Advisory board
            - Hiring plan
            
            ## 9. FINANCIAL PROJECTIONS
            - 5-year P&L projection
            - Cash flow analysis
            - Break-even analysis
            - Key financial ratios
            - Funding requirements
            
            ## 10. RISK ANALYSIS
            - Market risks
            - Operational risks
            - Financial risks
            - Mitigation strategies
            
            Mínimo 4000 palabras con números específicos y análisis detallado.
            """,
            
            'marketing_plan': f"""
            Crea un MARKETING PLAN COMPLETO Y ESTRATÉGICO para esta startup.
            
            PROYECTO: {project_data.get('name', 'Mi Startup')}
            INDUSTRIA: {project_data.get('industry', 'Technology')}
            DESCRIPCIÓN: {project_data.get('description', '')}
            
            REQUISITOS ESPECÍFICOS:
            {user_requirements}
            
            PLAN COMPLETO:
            
            ## 1. SITUATION ANALYSIS
            - Current market position
            - SWOT analysis
            - Customer insights
            - Competitive landscape
            
            ## 2. TARGET AUDIENCE
            - Primary personas (3-5 detailed profiles)
            - Secondary audiences
            - Customer journey mapping
            - Pain points y motivations
            
            ## 3. BRAND POSITIONING
            - Brand identity y personality
            - Unique value proposition
            - Brand messaging framework
            - Tone of voice
            
            ## 4. MARKETING OBJECTIVES
            - SMART goals (1-2 años)
            - KPIs y métricas
            - Budget allocation
            - ROI expectations
            
            ## 5. MARKETING STRATEGY
            - Content marketing strategy
            - SEO/SEM strategy
            - Social media strategy
            - Email marketing
            - Influencer partnerships
            - PR y media outreach
            
            ## 6. CHANNEL STRATEGY
            - Digital channels priority
            - Offline channels (si aplica)
            - Channel integration
            - Attribution modeling
            
            ## 7. CONTENT CALENDAR
            - Editorial calendar (3 meses)
            - Content pillars
            - Content formats
            - Distribution schedule
            
            ## 8. BUDGET & RESOURCES
            - Marketing budget breakdown
            - Team requirements
            - Tools y software needed
            - Expected CAC/LTV
            
            ## 9. IMPLEMENTATION TIMELINE
            - 90-day action plan
            - Monthly milestones
            - Key deliverables
            - Risk mitigation
            
            ## 10. MEASUREMENT & OPTIMIZATION
            - Analytics setup
            - Reporting framework
            - A/B testing plan
            - Optimization process
            
            Incluir ejemplos específicos, números y tácticas accionables. Mínimo 3000 palabras.
            """
        }
        
        # Generar documento con Gemini
        model = genai.GenerativeModel(MODEL_NAME)
        response = model.generate_content(
            prompts[document_type],
            generation_config={
                "temperature": 0.7,
                "top_p": 0.95,
                "top_k": 40,
                "max_output_tokens": 8000,  # Máximo para documentos extensos
            }
        )
        
        # Cobrar créditos
        credits_after = charge_credits(user['id'], credits_required)
        if credits_after is None:
            return jsonify({'error': 'Could not charge credits'}), 500
        
        # Guardar documento
        document_id = str(uuid.uuid4())
        title = f"{document_type.replace('_', ' ').title()} - {project_data.get('name', 'Mi Startup')}"
        
        with engine.connect() as conn:
            conn.execute(
                text("""
                    INSERT INTO generated_documents (
                        id, user_id, bot_used, document_type, title, content, 
                        format, metadata, credits_used, created_at, updated_at
                    ) VALUES (
                        :id, :user_id, :bot_used, :document_type, :title, :content,
                        'markdown', :metadata, :credits_used, NOW(), NOW()
                    )
                """),
                {
                    "id": document_id,
                    "user_id": user['id'],
                    "bot_used": bot_id,
                    "document_type": document_type,
                    "title": title,
                    "content": response.text,
                    "metadata": json.dumps({
                        "project_id": project_id,
                        "word_count": len(response.text.split()),
                        "generated_at": datetime.now().isoformat(),
                        "user_requirements": user_requirements
                    }),
                    "credits_used": credits_required
                }
            )
            conn.commit()
        
        return jsonify({
            'success': True,
            'document_id': document_id,
            'title': title,
            'document_type': document_type,
            'content_preview': response.text[:500] + '...',
            'word_count': len(response.text.split()),
            'credits_used': credits_required,
            'credits_remaining': credits_after,
            'download_url': f'/documents/{document_id}/download',
            'view_url': f'/documents/{document_id}/view'
        })
        
    except Exception as e:
        print(f"❌ Error generating document: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Could not generate document: {str(e)}'}), 500

@app.route('/documents/<document_id>/view', methods=['GET'])
@require_auth
def view_document(user, document_id):
    """Ver contenido completo del documento"""
    try:
        with engine.connect() as conn:
            result = conn.execute(
                text("""
                    SELECT title, content, document_type, created_at, metadata, bot_used
                    FROM generated_documents 
                    WHERE id = :document_id AND user_id = :user_id
                """),
                {"document_id": document_id, "user_id": user['id']}
            ).fetchone()
            
            if not result:
                return jsonify({'error': 'Document not found'}), 404
            
            # Incrementar contador de views
            conn.execute(
                text("UPDATE generated_documents SET download_count = download_count + 1 WHERE id = :document_id"),
                {"document_id": document_id}
            )
            conn.commit()
        
        return jsonify({
            'success': True,
            'document_id': document_id,
            'title': result[0],
            'content': result[1],
            'document_type': result[2],
            'created_at': result[3].isoformat(),
            'metadata': json.loads(result[4]) if result[4] else {},
            'bot_used': result[5]
        })
        
    except Exception as e:
        print(f"❌ Error viewing document: {e}")
        return jsonify({'error': 'Could not view document'}), 500

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'docx', 'doc', 'md'}
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16MB

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def extract_text_from_file(file_path, file_extension):
    """Extrae texto de diferentes tipos de archivo"""
    try:
        if file_extension == 'txt' or file_extension == 'md':
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        
        elif file_extension == 'pdf':
            text = ""
            with open(file_path, 'rb') as f:
                pdf_reader = PyPDF2.PdfReader(f)
                for page in pdf_reader.pages:
                    text += page.extract_text() + "\n"
            return text
        
        elif file_extension in ['docx', 'doc']:
            doc = docx.Document(file_path)
            text = ""
            for paragraph in doc.paragraphs:
                text += paragraph.text + "\n"
            return text
        
        else:
            return "Formato de archivo no soportado"
            
    except Exception as e:
        print(f"❌ Error extracting text: {e}")
        return f"Error extrayendo texto: {str(e)}"

@app.route('/documents/upload', methods=['POST'])
@require_auth
def upload_document(user):
    """Upload y análisis de documentos del usuario"""
    try:
        # Verificar que hay archivo
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        project_id = request.form.get('project_id')
        document_purpose = request.form.get('purpose', 'general')  # 'analysis', 'reference', 'improvement'
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not project_id:
            return jsonify({'error': 'project_id is required'}), 400
        
        # Verificar proyecto
        with engine.connect() as conn:
            project_result = conn.execute(
                text("SELECT id FROM projects WHERE id = :project_id AND user_id = :user_id"),
                {"project_id": project_id, "user_id": user['id']}
            ).fetchone()
            
            if not project_result:
                return jsonify({'error': 'Project not found'}), 404
        
        # Verificar archivo
        if not allowed_file(file.filename):
            return jsonify({
                'error': 'File type not allowed',
                'allowed_types': list(ALLOWED_EXTENSIONS)
            }), 400
        
        # Verificar tamaño
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)
        
        if file_size > MAX_FILE_SIZE:
            return jsonify({
                'error': 'File too large',
                'max_size_mb': MAX_FILE_SIZE / (1024 * 1024)
            }), 400
        
        # Guardar archivo temporalmente
        filename = secure_filename(file.filename)
        file_extension = filename.rsplit('.', 1)[1].lower()
        
        with tempfile.NamedTemporaryFile(delete=False, suffix=f'.{file_extension}') as temp_file:
            file.save(temp_file.name)
            temp_path = temp_file.name
        
        try:
            # Extraer texto del archivo
            extracted_text = extract_text_from_file(temp_path, file_extension)
            
            # Analizar documento con Gemini
            analysis = analyze_document_with_gemini(extracted_text, document_purpose, filename)
            
            # Guardar en base de datos
            document_id = str(uuid.uuid4())
            
            with engine.connect() as conn:
                conn.execute(
                    text("""
                        INSERT INTO generated_documents (
                            id, user_id, bot_used, document_type, title, content, 
                            format, metadata, credits_used, created_at, updated_at
                        ) VALUES (
                            :id, :user_id, 'document_upload', 'uploaded_document', :title, :content,
                            :format, :metadata, 0, NOW(), NOW()
                        )
                    """),
                    {
                        "id": document_id,
                        "user_id": user['id'],
                        "title": f"📄 {filename}",
                        "content": extracted_text,
                        "format": file_extension,
                        "metadata": json.dumps({
                            "original_filename": filename,
                            "file_size": file_size,
                            "project_id": project_id,
                            "purpose": document_purpose,
                            "uploaded_at": datetime.now().isoformat(),
                            "analysis": analysis,
                            "file_type": file_extension,
                            "character_count": len(extracted_text),
                            "word_count": len(extracted_text.split())
                        })
                    }
                )
                conn.commit()
            
            # Limpiar archivo temporal
            os.unlink(temp_path)
            
            return jsonify({
                'success': True,
                'document_id': document_id,
                'filename': filename,
                'file_size': file_size,
                'text_extracted': len(extracted_text) > 0,
                'word_count': len(extracted_text.split()),
                'analysis': analysis,
                'view_url': f'/documents/{document_id}/view'
            })
            
        except Exception as e:
            # Limpiar archivo temporal en caso de error
            if os.path.exists(temp_path):
                os.unlink(temp_path)
            raise e
        
    except Exception as e:
        print(f"❌ Error uploading document: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Could not upload document: {str(e)}'}), 500

def analyze_document_with_gemini(text, purpose, filename):
    """Analiza el documento subido con Gemini"""
    try:
        analysis_prompts = {
            'analysis': f"""
            Analiza este documento y proporciona un resumen ejecutivo profesional.
            
            Documento: {filename}
            
            Contenido:
            {text[:4000]}  # Primeros 4000 caracteres
            
            Proporciona:
            1. **Tipo de documento**: ¿Qué tipo de documento es?
            2. **Resumen ejecutivo**: Resumen en 2-3 párrafos
            3. **Puntos clave**: 5 puntos más importantes
            4. **Fortalezas identificadas**: Qué está bien
            5. **Áreas de mejora**: Qué se puede mejorar
            6. **Recomendaciones**: 3 acciones específicas
            """,
            
            'improvement': f"""
            Actúa como consultor experto y analiza este documento para mejorarlo.
            
            Documento: {filename}
            
            Contenido:
            {text[:4000]}
            
            Proporciona análisis detallado:
            1. **Fortalezas actuales**: Qué funciona bien
            2. **Debilidades identificadas**: Problemas específicos
            3. **Mejoras estructurales**: Cómo reorganizar
            4. **Mejoras de contenido**: Qué añadir/quitar
            5. **Plan de acción**: 5 pasos para mejorar
            6. **Versión mejorada**: Propuesta de estructura mejor
            """,
            
            'reference': f"""
            Este documento se usará como referencia. Analiza y extrae información útil.
            
            Documento: {filename}
            
            Contenido:
            {text[:4000]}
            
            Extrae:
            1. **Información clave**: Datos importantes
            2. **Métricas y números**: Cifras relevantes
            3. **Conceptos aplicables**: Ideas que se pueden usar
            4. **Referencias útiles**: Fuentes o contactos
            5. **Aplicación práctica**: Cómo usar esta información
            """
        }
        
        prompt = analysis_prompts.get(purpose, analysis_prompts['analysis'])
        
        model = genai.GenerativeModel(MODEL_NAME)
        response = model.generate_content(
            prompt,
            generation_config={
                "temperature": 0.5,
                "max_output_tokens": 2000,
            }
        )
        
        return {
            "analysis_type": purpose,
            "analysis_content": response.text,
            "analyzed_at": datetime.now().isoformat(),
            "analysis_length": len(response.text)
        }
        
    except Exception as e:
        print(f"❌ Error analyzing document: {e}")
        return {
            "analysis_type": purpose,
            "analysis_content": f"Error analizando documento: {str(e)}",
            "analyzed_at": datetime.now().isoformat(),
            "error": True
        }

@app.route('/documents/uploaded', methods=['GET'])
@require_auth
def get_uploaded_documents(user):
    """Obtiene documentos subidos por el usuario"""
    try:
        project_id = request.args.get('project_id')
        
        base_query = """
            SELECT id, title, created_at, metadata
            FROM generated_documents 
            WHERE user_id = :user_id AND document_type = 'uploaded_document'
        """
        
        params = {"user_id": user['id']}
        
        if project_id:
            base_query += " AND JSON_EXTRACT(metadata, '$.project_id') = :project_id"
            params["project_id"] = project_id
        
        base_query += " ORDER BY created_at DESC"
        
        with engine.connect() as conn:
            result = conn.execute(text(base_query), params).fetchall()
            
            documents = []
            for row in result:
                metadata = json.loads(row[3]) if row[3] else {}
                
                documents.append({
                    'id': str(row[0]),
                    'title': row[1],
                    'original_filename': metadata.get('original_filename', 'Unknown'),
                    'file_size': metadata.get('file_size', 0),
                    'file_type': metadata.get('file_type', 'unknown'),
                    'purpose': metadata.get('purpose', 'general'),
                    'word_count': metadata.get('word_count', 0),
                    'uploaded_at': row[2].isoformat(),
                    'has_analysis': 'analysis' in metadata,
                    'view_url': f'/documents/{row[0]}/view'
                })
        
        return jsonify({
            'success': True,
            'uploaded_documents': documents,
            'total_count': len(documents)
        })
        
    except Exception as e:
        print(f"❌ Error getting uploaded documents: {e}")
        return jsonify({'error': 'Could not get uploaded documents'}), 500
        
# ==============================================================================
#           MAIN
# ==============================================================================

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🔥 0BULLSHIT BACKEND V2.0 - CORS KILLER EDITION!")
    print("="*60)
    print("✅ CORS completamente arreglado!")
    print("✅ Chat sessions implementado!")
    print("✅ Todos los endpoints funcionando!")
    print("✅ Sistema de autenticación completo!")
    print("✅ Base de datos conectada!")
    print("✅ Gemini AI configurado!")
    print("✅ Sistema de memoria neuronal!")
    print("✅ Sistema de créditos y suscripciones!")
    print("="*60)
    print(f"🚀 Servidor iniciando en puerto {os.environ.get('PORT', 8080)}")
    print("🌐 Endpoints disponibles:")
    print("   - GET  /              - Home")
    print("   - GET  /cors-test     - Test CORS")
    print("   - GET  /health        - Health check")
    print("   - POST /auth/register - Registro")
    print("   - POST /auth/login    - Login")
    print("   - POST /auth/google   - Google Auth")
    print("   - GET  /user/profile  - Perfil usuario")
    print("   - GET  /credits/balance - Balance créditos")
    print("   - POST /chat/bot      - Chat con bot")
    print("   - POST /chat/new      - Nueva conversación")
    print("   - GET  /chat/history  - Historial")
    print("   - GET  /chat/stats    - Estadísticas chat")
    print("   - GET  /projects      - Proyectos")
    print("   - GET  /bots/available- Bots disponibles")
    print("   - POST /subscription/upgrade - Upgrade plan")
    print("   - GET  /admin/users   - Admin: usuarios")
    print("="*60)
    print("🎯 CORS KILLER ESTÁ ACTIVO - NO MÁS PROBLEMAS!")
    print("💡 Para testear CORS: GET /cors-test")
    print("🔐 Autenticación: Bearer Token en Authorization header")
    print("🤖 AI: Gemini 2.0 Flash integrado")
    print("🗄️ Base de datos: PostgreSQL/Supabase")
    print("="*60)
    
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)), debug=True)
