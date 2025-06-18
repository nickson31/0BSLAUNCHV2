import os
import markdown
from typing import Dict, Any, Optional
from datetime import datetime
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from io import BytesIO

def save_markdown(content: str, metadata: Dict[str, Any]) -> str:
    """Save markdown content to file."""
    filename = f"{metadata['title']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    filepath = os.path.join('documents', filename)
    
    os.makedirs('documents', exist_ok=True)
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
    
    return filepath

def markdown_to_html(markdown_content: str) -> str:
    """Convert markdown to HTML."""
    return markdown.markdown(markdown_content, extensions=['extra', 'codehilite'])

def markdown_to_pdf(markdown_content: str, metadata: Dict[str, Any]) -> BytesIO:
    """Convert markdown to PDF."""
    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    
    # Add title
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, height - 50, metadata['title'])
    
    # Add content
    c.setFont("Helvetica", 12)
    y = height - 100
    for line in markdown_content.split('\n'):
        if y < 50:  # New page if we're at the bottom
            c.showPage()
            y = height - 50
        c.drawString(50, y, line)
        y -= 15
    
    c.save()
    buffer.seek(0)
    return buffer

def get_document_path(doc_id: str, format: str) -> Optional[str]:
    """Get document path by ID and format."""
    base_path = os.path.join('documents', doc_id)
    if format == 'markdown':
        return f"{base_path}.md"
    elif format == 'html':
        return f"{base_path}.html"
    elif format == 'pdf':
        return f"{base_path}.pdf"
    return None

def cleanup_old_documents(max_age_days: int = 30) -> None:
    """Clean up documents older than max_age_days."""
    current_time = datetime.now()
    documents_dir = 'documents'
    
    if not os.path.exists(documents_dir):
        return
    
    for filename in os.listdir(documents_dir):
        filepath = os.path.join(documents_dir, filename)
        file_time = datetime.fromtimestamp(os.path.getctime(filepath))
        age_days = (current_time - file_time).days
        
        if age_days > max_age_days:
            os.remove(filepath) 