#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
0Bullshit Backend v2.0 - Database Setup Script
Configuración automática de la base de datos con schema completo
"""

import os
import sys
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
import sqlalchemy
from sqlalchemy import text
from urllib.parse import urlparse
import time

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def get_database_config():
    """Obtiene configuración de base de datos desde variables de entorno"""
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        print("❌ ERROR: DATABASE_URL environment variable not found")
        print("Please set your database URL in .env file or environment")
        sys.exit(1)
    
    # Parse URL
    parsed = urlparse(database_url)
    
    return {
        'host': parsed.hostname,
        'port': parsed.port or 5432,
        'username': parsed.username,
        'password': parsed.password,
        'database': parsed.path[1:] if parsed.path.startswith('/') else parsed.path,
        'full_url': database_url
    }

def test_connection(config):
    """Testa conexión a la base de datos"""
    try:
        print(f"🔗 Testing connection to {config['host']}:{config['port']}...")
        
        # Connect to PostgreSQL server (not specific database)
        conn = psycopg2.connect(
            host=config['host'],
            port=config['port'],
            user=config['username'],
            password=config['password'],
            database='postgres'  # Connect to default postgres database
        )
        conn.close()
        
        print("✅ Database connection successful!")
        return True
        
    except psycopg2.Error as e:
        print(f"❌ Database connection failed: {e}")
        return False

def create_database_if_not_exists(config):
    """Crea la base de datos si no existe"""
    try:
        print(f"🗄️ Checking if database '{config['database']}' exists...")
        
        # Connect to PostgreSQL server
        conn = psycopg2.connect(
            host=config['host'],
            port=config['port'],
            user=config['username'],
            password=config['password'],
            database='postgres'
        )
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        
        cursor = conn.cursor()
        
        # Check if database exists
        cursor.execute(
            "SELECT 1 FROM pg_catalog.pg_database WHERE datname = %s",
            (config['database'],)
        )
        
        if cursor.fetchone():
            print(f"✅ Database '{config['database']}' already exists")
        else:
            print(f"📝 Creating database '{config['database']}'...")
            cursor.execute(f'CREATE DATABASE "{config["database"]}"')
            print(f"✅ Database '{config['database']}' created successfully!")
        
        cursor.close()
        conn.close()
        return True
        
    except psycopg2.Error as e:
        print(f"❌ Error creating database: {e}")
        return False

def load_schema():
    """Carga el schema SQL desde archivo"""
    schema_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'database',
        'schema.sql'
    )
    
    if not os.path.exists(schema_path):
        print(f"❌ Schema file not found at: {schema_path}")
        return None
    
    try:
        with open(schema_path, 'r', encoding='utf-8') as f:
            schema_sql = f.read()
        
        print(f"📄 Schema loaded from {schema_path}")
        return schema_sql
        
    except Exception as e:
        print(f"❌ Error loading schema: {e}")
        return None

def execute_schema(config, schema_sql):
    """Ejecuta el schema SQL en la base de datos"""
    try:
        print("🔧 Creating SQLAlchemy engine...")
        engine = sqlalchemy.create_engine(config['full_url'])
        
        print("📋 Executing schema SQL...")
        
        with engine.connect() as conn:
            # Split SQL into individual statements
            statements = [stmt.strip() for stmt in schema_sql.split(';') if stmt.strip()]
            
            print(f"📝 Executing {len(statements)} SQL statements...")
            
            for i, statement in enumerate(statements, 1):
                if statement.upper().startswith(('CREATE', 'ALTER', 'INSERT', 'COMMENT')):
                    try:
                        conn.execute(text(statement))
                        if i % 10 == 0:  # Progress indicator
                            print(f"  ✅ Executed {i}/{len(statements)} statements")
                    except Exception as e:
                        # Some statements might fail if already exist (like extensions)
                        if 'already exists' not in str(e).lower():
                            print(f"  ⚠️ Warning executing statement {i}: {e}")
            
            conn.commit()
        
        print("✅ Schema executed successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Error executing schema: {e}")
        return False

def verify_tables(config):
    """Verifica que las tablas se crearon correctamente"""
    try:
        print("🔍 Verifying table creation...")
        engine = sqlalchemy.create_engine(config['full_url'])
        
        with engine.connect() as conn:
            # Get list of tables
            result = conn.execute(text("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'public' 
                ORDER BY table_name
            """))
            
            tables = [row[0] for row in result]
            
            expected_tables = [
                'users', 'subscriptions', 'credit_transactions',
                'neural_memory', 'neural_interactions', 'bot_usage_stats',
                'investors', 'employees', 'search_history', 'saved_entities',
                'outreach_templates', 'outreach_campaigns', 'outreach_messages',
                'generated_documents', 'document_versions', 'platform_analytics',
                'user_sessions'
            ]
            
            print(f"📊 Found {len(tables)} tables:")
            for table in tables:
                status = "✅" if table in expected_tables else "ℹ️"
                print(f"  {status} {table}")
            
            missing_tables = set(expected_tables) - set(tables)
            if missing_tables:
                print(f"⚠️ Missing expected tables: {missing_tables}")
            else:
                print("✅ All expected tables found!")
            
            return len(missing_tables) == 0
        
    except Exception as e:
        print(f"❌ Error verifying tables: {e}")
        return False

def create_initial_data(config):
    """Crea datos iniciales necesarios"""
    try:
        print("📥 Creating initial data...")
        engine = sqlalchemy.create_engine(config['full_url'])
        
        with engine.connect() as conn:
            # Check if initial data already exists
            result = conn.execute(text("""
                SELECT COUNT(*) FROM platform_analytics 
                WHERE metric_name = 'total_users'
            """))
            
            if result.scalar() > 0:
                print("ℹ️ Initial data already exists")
                return True
            
            # Insert initial platform analytics
            conn.execute(text("""
                INSERT INTO platform_analytics (date, metric_name, metric_value) VALUES
                (CURRENT_DATE, 'total_users', 0),
                (CURRENT_DATE, 'active_users_today', 0),
                (CURRENT_DATE, 'total_credits_spent', 0),
                (CURRENT_DATE, 'total_bot_interactions', 0)
            """))
            
            conn.commit()
            print("✅ Initial data created!")
            return True
        
    except Exception as e:
        print(f"❌ Error creating initial data: {e}")
        return False

def setup_extensions(config):
    """Configura extensiones necesarias"""
    try:
        print("🔌 Setting up PostgreSQL extensions...")
        engine = sqlalchemy.create_engine(config['full_url'])
        
        extensions = ['uuid-ossp', 'pgcrypto']
        
        with engine.connect() as conn:
            for ext in extensions:
                try:
                    conn.execute(text(f'CREATE EXTENSION IF NOT EXISTS "{ext}"'))
                    print(f"  ✅ Extension {ext} enabled")
                except Exception as e:
                    print(f"  ⚠️ Could not enable extension {ext}: {e}")
            
            conn.commit()
        
        return True
        
    except Exception as e:
        print(f"❌ Error setting up extensions: {e}")
        return False

def main():
    """Función principal del setup"""
    print("🚀 0Bullshit Backend v2.0 - Database Setup")
    print("=" * 50)
    
    # Get database configuration
    config = get_database_config()
    
    # Test connection
    if not test_connection(config):
        print("\n❌ Setup failed: Cannot connect to database")
        sys.exit(1)
    
    # Create database if not exists
    if not create_database_if_not_exists(config):
        print("\n❌ Setup failed: Cannot create database")
        sys.exit(1)
    
    # Setup extensions
    if not setup_extensions(config):
        print("\n⚠️ Warning: Some extensions could not be enabled")
    
    # Load schema
    schema_sql = load_schema()
    if not schema_sql:
        print("\n❌ Setup failed: Cannot load schema")
        sys.exit(1)
    
    # Execute schema
    if not execute_schema(config, schema_sql):
        print("\n❌ Setup failed: Cannot execute schema")
        sys.exit(1)
    
    # Verify tables
    if not verify_tables(config):
        print("\n⚠️ Warning: Some tables might be missing")
    
    # Create initial data
    if not create_initial_data(config):
        print("\n⚠️ Warning: Could not create initial data")
    
    print("\n" + "=" * 50)
    print("🎉 Database setup completed successfully!")
    print("\nNext steps:")
    print("1. Set your API keys in .env file")
    print("2. Run: python app.py")
    print("3. Visit: http://localhost:8080")
    print("\n🚀 Happy coding!")

if __name__ == "__main__":
    main()
