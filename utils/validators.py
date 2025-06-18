from typing import Dict, Any, Optional
import re
from datetime import datetime

def validate_email(email: str) -> bool:
    """Validate email format."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def validate_password(password: str) -> bool:
    """Validate password strength."""
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'\d', password):
        return False
    return True

def validate_user_input(data: Dict[str, Any]) -> Optional[str]:
    """Validate user registration/login input."""
    if not data.get('email'):
        return 'Email is required'
    if not validate_email(data['email']):
        return 'Invalid email format'
    
    if 'password' in data:
        if not data['password']:
            return 'Password is required'
        if not validate_password(data['password']):
            return 'Password must be at least 8 characters and contain uppercase, lowercase, and numbers'
    
    return None

def validate_document_metadata(metadata: Dict[str, Any]) -> Optional[str]:
    """Validate document metadata."""
    required_fields = ['title', 'type', 'user_id']
    for field in required_fields:
        if field not in metadata:
            return f'{field} is required'
    
    if not isinstance(metadata['title'], str) or len(metadata['title']) > 255:
        return 'Invalid title format'
    
    if not isinstance(metadata['type'], str) or metadata['type'] not in ['markdown', 'html', 'pdf']:
        return 'Invalid document type'
    
    return None

def validate_chat_input(data: Dict[str, Any]) -> Optional[str]:
    """Validate chat input."""
    if not data.get('message'):
        return 'Message is required'
    if not isinstance(data['message'], str):
        return 'Message must be a string'
    if len(data['message']) > 10000:
        return 'Message is too long'
    
    return None 