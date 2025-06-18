# -*- coding: utf-8 -*-

"""
0Bullshit Backend v2.0 - Sistema de Documentos Mejorado
Funciones para crear, mostrar, almacenar y gestionar archivos generados por bots
"""

import os
import uuid
import json
from datetime import datetime
from sqlalchemy import text
from flask import jsonify, send_file, request
import markdown
from reportlab.pdfgenerator import PDFGenerator
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
import zipfile
import tempfile

# ==============================================================================
#           DOCUMENT STORAGE FUNCTIONS
# ==============================================================================

def save_generated_document(user_id, bot_id, content, document_type, title, 
                           format_type="markdown", metadata=None):
    """
    Guarda un documento generado por un bot en la base de datos
    """
    try:
        document_id = str(uuid.uuid4())
        
        # Determinar créditos usados basado en el bot
        credits_used = get_bot_credit_cost(bot_id)
        
        query = """
        INSERT INTO generated_documents 
        (id, user_id, bot_used, document_type, title, content, format, metadata, credits_used, created_at, updated_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        params = (
            document_id, user_id, bot_id, document_type, title, content,
            format_type, json.dumps(metadata or {}), credits_used,
            datetime.now(), datetime.now()
        )
        
        with engine.connect() as conn:
            conn.execute(text(query), params)
            conn.commit()
        
        print(f"✅ Document saved: {document_id} by bot {bot_id}")
        
        return {
            "success": True,
            "document_id": document_id,
            "title": title,
            "format": format_type,
            "credits_used": credits_used
        }
        
    except Exception as e:
        print(f"❌ Error saving document: {e}")
        return {"error": "Failed to save document"}

def get_user_documents(user_id, limit=20, document_type=None):
    """
    Obtiene todos los documentos generados por un usuario
    """
    try:
        base_query = """
        SELECT id, bot_used, document_type, title, format, metadata, 
               credits_used, created_at, download_count, is_public
        FROM generated_documents 
        WHERE user_id = %s
        """
        
        params = [user_id]
        
        if document_type:
            base_query += " AND document_type = %s"
            params.append(document_type)
        
        base_query += " ORDER BY created_at DESC LIMIT %s"
        params.append(limit)
        
        result = pd.read_sql(base_query, engine, params=params)
        
        if result.empty:
            return []
        
        documents = []
        for _, doc in result.iterrows():
            documents.append({
                "id": doc['id'],
                "bot_used": doc['bot_used'],
                "document_type": doc['document_type'],
                "title": doc['title'],
                "format": doc['format'],
                "metadata": json.loads(doc['metadata']) if doc['metadata'] else {},
                "credits_used": doc['credits_used'],
                "created_at": doc['created_at'].isoformat(),
                "download_count": doc['download_count'],
                "is_public": doc['is_public'],
                "download_url": f"/documents/{doc['id']}/download",
                "view_url": f"/documents/{doc['id']}/view"
            })
        
        return documents
        
    except Exception as e:
        print(f"❌ Error getting user documents: {e}")
        return []

def get_document_content(document_id, user_id=None):
    """
    Obtiene el contenido completo de un documento
    """
    try:
        query = """
        SELECT user_id, bot_used, document_type, title, content, format, 
               metadata, created_at, is_public
        FROM generated_documents 
        WHERE id = %s
        """
        
        result = pd.read_sql(query, engine, params=[document_id])
        
        if result.empty:
            return None
        
        doc = result.iloc[0]
        
        # Verificar permisos
        if not doc['is_public'] and user_id != doc['user_id']:
            return {"error": "Access denied"}
        
        # Incrementar contador de descargas
        update_download_count(document_id)
        
        return {
            "id": document_id,
            "user_id": doc['user_id'],
            "bot_used": doc['bot_used'],
            "document_type": doc['document_type'],
            "title": doc['title'],
            "content": doc['content'],
            "format": doc['format'],
            "metadata": json.loads(doc['metadata']) if doc['metadata'] else {},
            "created_at": doc['created_at'].isoformat(),
            "is_public": doc['is_public']
        }
        
    except Exception as e:
        print(f"❌ Error getting document content: {e}")
        return None

def update_download_count(document_id):
    """Incrementa el contador de descargas"""
    try:
        query = """
        UPDATE generated_documents 
        SET download_count = download_count + 1 
        WHERE id = %s
        """
        
        with engine.connect() as conn:
            conn.execute(text(query), [document_id])
            conn.commit()
            
    except Exception as e:
        print(f"❌ Error updating download count: {e}")

# ==============================================================================
#           DOCUMENT CONVERSION FUNCTIONS
# ==============================================================================

def convert_markdown_to_html(markdown_content, title="Document"):
    """Convierte markdown a HTML"""
    try:
        html_content = markdown.markdown(markdown_content, extensions=['tables', 'fenced_code'])
        
        full_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>{title}</title>
            <meta charset="UTF-8">
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    line-height: 1.6;
                    max-width: 800px;
                    margin: 0 auto;
                    padding: 20px;
                    color: #333;
                }}
                h1, h2, h3 {{ color: #2c3e50; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                code {{ background-color: #f4f4f4; padding: 2px 4px; border-radius: 3px; }}
                pre {{ background-color: #f4f4f4; padding: 10px; border-radius: 5px; overflow-x: auto; }}
                blockquote {{ border-left: 4px solid #3498db; margin: 0; padding-left: 20px; color: #666; }}
            </style>
        </head>
        <body>
            {html_content}
            <hr>
            <p><small>Generated by 0Bullshit AI • {datetime.now().strftime('%Y-%m-%d %H:%M')}</small></p>
        </body>
        </html>
        """
        
        return full_html
        
    except Exception as e:
        print(f"❌ Error converting markdown to HTML: {e}")
        return f"<html><body><h1>Error</h1><p>Could not convert document: {e}</p></body></html>"

def convert_markdown_to_pdf(markdown_content, title="Document"):
    """Convierte markdown a PDF"""
    try:
        # Crear archivo temporal
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
        
        # Crear documento PDF
        doc = SimpleDocTemplate(temp_file.name, pagesize=letter)
        styles = getSampleStyleSheet()
        
        # Convertir markdown a elementos PDF
        story = []
        
        # Título
        title_style = styles['Title']
        story.append(Paragraph(title, title_style))
        story.append(Spacer(1, 20))
        
        # Contenido (simplificado - en producción usar parser más avanzado)
        lines = markdown_content.split('\n')
        for line in lines:
            if line.startswith('# '):
                story.append(Paragraph(line[2:], styles['Heading1']))
            elif line.startswith('## '):
                story.append(Paragraph(line[3:], styles['Heading2']))
            elif line.startswith('### '):
                story.append(Paragraph(line[4:], styles['Heading3']))
            elif line.strip():
                story.append(Paragraph(line, styles['Normal']))
                story.append(Spacer(1, 6))
        
        # Footer
        story.append(Spacer(1, 30))
        footer_text = f"Generated by 0Bullshit AI • {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        story.append(Paragraph(footer_text, styles['Normal']))
        
        # Construir PDF
        doc.build(story)
        
        return temp_file.name
        
    except Exception as e:
        print(f"❌ Error converting to PDF: {e}")
        return None

def create_document_archive(documents, user_id):
    """Crea un archivo ZIP con múltiples documentos"""
    try:
        temp_zip = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
        
        with zipfile.ZipFile(temp_zip.name, 'w') as zip_file:
            for doc_id in documents:
                doc = get_document_content(doc_id, user_id)
                if doc and 'content' in doc:
                    # Crear nombre de archivo
                    safe_title = "".join(c for c in doc['title'] if c.isalnum() or c in (' ', '-', '_')).rstrip()
                    filename = f"{safe_title}.{doc['format']}"
                    
                    # Añadir al ZIP
                    zip_file.writestr(filename, doc['content'])
        
        return temp_zip.name
        
    except Exception as e:
        print(f"❌ Error creating document archive: {e}")
        return None

# ==============================================================================
#           ENHANCED BOT RESPONSE PROCESSING
# ==============================================================================

def enhanced_process_bot_response(response_text, output_format, bot_id, user_id, user_context):
    """
    Procesamiento mejorado que automáticamente guarda documentos generados
    """
    try:
        # Procesar respuesta según formato
        processed = process_bot_response(response_text, output_format)
        
        # Si es un documento, guardarlo automáticamente
        if processed.get("downloadable") or "document" in output_format:
            
            # Generar título inteligente
            title = generate_document_title(response_text, bot_id, user_context)
            
            # Determinar tipo de documento
            document_type = determine_document_type(bot_id, output_format)
            
            # Extraer metadata
            metadata = extract_document_metadata(response_text, bot_id, user_context)
            
            # Guardar en base de datos
            save_result = save_generated_document(
                user_id=user_id,
                bot_id=bot_id,
                content=response_text,
                document_type=document_type,
                title=title,
                format_type=determine_format(output_format),
                metadata=metadata
            )
            
            if save_result.get("success"):
                # Añadir información del documento guardado
                processed["document_saved"] = True
                processed["document_id"] = save_result["document_id"]
                processed["document_title"] = title
                processed["download_url"] = f"/documents/{save_result['document_id']}/download"
                processed["view_url"] = f"/documents/{save_result['document_id']}/view"
        
        return processed
        
    except Exception as e:
        print(f"❌ Error in enhanced processing: {e}")
        return process_bot_response(response_text, output_format)

def generate_document_title(content, bot_id, user_context):
    """Genera título inteligente para el documento"""
    try:
        # Títulos por bot
        bot_titles = {
            "pitch_deck_master": f"Pitch Deck - {user_context.get('startup_name', 'Mi Startup')}",
            "financial_modeler": f"Modelo Financiero - {datetime.now().strftime('%Y-%m')}",
            "market_analyzer": f"Análisis de Mercado - {user_context.get('industry', 'Sector')}",
            "business_model_innovator": f"Modelo de Negocio - {user_context.get('industry', 'Innovador')}",
            "strategy_consultant": f"Estrategia Empresarial - {datetime.now().strftime('%Y-%m-%d')}",
            "content_machine": f"Estrategia de Contenido - {user_context.get('topic', 'Marketing')}",
            "legal_guardian": f"Documentos Legales - {datetime.now().strftime('%Y-%m-%d')}",
            "cfo_virtual": f"Reporte Financiero - {datetime.now().strftime('%Y-%m')}"
        }
        
        return bot_titles.get(bot_id, f"Documento - {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        
    except Exception as e:
        return f"Documento - {datetime.now().strftime('%Y-%m-%d %H:%M')}"

def determine_document_type(bot_id, output_format):
    """Determina el tipo de documento basado en el bot"""
    type_mapping = {
        "pitch_deck_master": "pitch_deck",
        "financial_modeler": "financial_model",
        "market_analyzer": "market_analysis", 
        "business_model_innovator": "business_model",
        "strategy_consultant": "strategy_document",
        "content_machine": "content_strategy",
        "legal_guardian": "legal_document",
        "cfo_virtual": "financial_report",
        "brand_builder": "brand_strategy",
        "seo_dominator": "seo_strategy"
    }
    
    return type_mapping.get(bot_id, "general_document")

def determine_format(output_format):
    """Determina el formato del archivo"""
    if "markdown" in output_format:
        return "markdown"
    elif "html" in output_format:
        return "html"
    elif "pdf" in output_format:
        return "pdf"
    else:
        return "markdown"  # Por defecto

def extract_document_metadata(content, bot_id, user_context):
    """Extrae metadata relevante del contenido"""
    try:
        metadata = {
            "word_count": len(content.split()),
            "character_count": len(content),
            "generated_at": datetime.now().isoformat(),
            "bot_version": "2.0",
            "user_context": user_context,
            "content_sections": count_sections(content)
        }
        
        # Metadata específica por tipo de bot
        if bot_id == "pitch_deck_master":
            metadata["slides_estimated"] = estimate_slides(content)
        elif bot_id == "financial_modeler":
            metadata["has_projections"] = "projection" in content.lower()
        elif bot_id == "market_analyzer":
            metadata["has_tam_sam_som"] = any(term in content.lower() for term in ["tam", "sam", "som"])
        
        return metadata
        
    except Exception as e:
        return {"error": str(e)}

def count_sections(content):
    """Cuenta secciones en el contenido markdown"""
    return len([line for line in content.split('\n') if line.startswith('#')])

def estimate_slides(content):
    """Estima número de slides para pitch deck"""
    sections = count_sections(content)
    return min(max(sections, 8), 15)  # Entre 8 y 15 slides típicamente

# ==============================================================================
#           API ENDPOINTS PARA DOCUMENTOS
# ==============================================================================

@app.route('/documents', methods=['GET'])
@require_auth
def get_user_documents_endpoint(user):
    """Obtiene todos los documentos del usuario"""
    try:
        document_type = request.args.get('type')
        limit = int(request.args.get('limit', 20))
        
        documents = get_user_documents(user['id'], limit, document_type)
        
        return jsonify({
            "documents": documents,
            "total_count": len(documents),
            "user_id": user['id']
        })
        
    except Exception as e:
        print(f"❌ Error getting documents: {e}")
        return jsonify({"error": "Could not get documents"}), 500

@app.route('/documents/<document_id>/view', methods=['GET'])
@require_auth
def view_document(user, document_id):
    """Ver contenido del documento"""
    try:
        doc = get_document_content(document_id, user['id'])
        
        if not doc:
            return jsonify({"error": "Document not found"}), 404
        
        if "error" in doc:
            return jsonify(doc), 403
        
        return jsonify(doc)
        
    except Exception as e:
        print(f"❌ Error viewing document: {e}")
        return jsonify({"error": "Could not view document"}), 500

@app.route('/documents/<document_id>/download', methods=['GET'])
@require_auth  
def download_document(user, document_id):
    """Descarga documento en formato solicitado"""
    try:
        format_type = request.args.get('format', 'markdown')  # markdown, html, pdf
        
        doc = get_document_content(document_id, user['id'])
        
        if not doc:
            return jsonify({"error": "Document not found"}), 404
        
        if "error" in doc:
            return jsonify(doc), 403
        
        # Generar archivo según formato
        if format_type == 'html':
            html_content = convert_markdown_to_html(doc['content'], doc['title'])
            temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.html')
            temp_file.write(html_content)
            temp_file.close()
            
            return send_file(
                temp_file.name,
                as_attachment=True,
                download_name=f"{doc['title']}.html",
                mimetype='text/html'
            )
            
        elif format_type == 'pdf':
            pdf_file = convert_markdown_to_pdf(doc['content'], doc['title'])
            if pdf_file:
                return send_file(
                    pdf_file,
                    as_attachment=True,
                    download_name=f"{doc['title']}.pdf",
                    mimetype='application/pdf'
                )
            else:
                return jsonify({"error": "Could not generate PDF"}), 500
                
        else:  # markdown (default)
            temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.md')
            temp_file.write(doc['content'])
            temp_file.close()
            
            return send_file(
                temp_file.name,
                as_attachment=True,
                download_name=f"{doc['title']}.md",
                mimetype='text/markdown'
            )
        
    except Exception as e:
        print(f"❌ Error downloading document: {e}")
        return jsonify({"error": "Could not download document"}), 500

@app.route('/documents/archive', methods=['POST'])
@require_auth
def download_document_archive(user):
    """Descarga múltiples documentos en ZIP"""
    try:
        data = request.json
        document_ids = data.get('document_ids', [])
        
        if not document_ids:
            return jsonify({"error": "No documents specified"}), 400
        
        zip_file = create_document_archive(document_ids, user['id'])
        
        if zip_file:
            return send_file(
                zip_file,
                as_attachment=True,
                download_name=f"documentos_0bullshit_{datetime.now().strftime('%Y%m%d')}.zip",
                mimetype='application/zip'
            )
        else:
            return jsonify({"error": "Could not create archive"}), 500
            
    except Exception as e:
        print(f"❌ Error creating archive: {e}")
        return jsonify({"error": "Could not create archive"}), 500

@app.route('/documents/<document_id>', methods=['DELETE'])
@require_auth
def delete_document(user, document_id):
    """Elimina un documento"""
    try:
        query = """
        DELETE FROM generated_documents 
        WHERE id = %s AND user_id = %s
        """
        
        with engine.connect() as conn:
            result = conn.execute(text(query), [document_id, user['id']])
            conn.commit()
            
            if result.rowcount == 0:
                return jsonify({"error": "Document not found"}), 404
        
        return jsonify({"message": "Document deleted successfully"})
        
    except Exception as e:
        print(f"❌ Error deleting document: {e}")
        return jsonify({"error": "Could not delete document"}), 500

print("📄 Enhanced document system loaded successfully!")
