# -*- coding: utf-8 -*-

"""
PARCHE DE INTEGRACIÓN PARA SISTEMA DE DOCUMENTOS
Añadir estas líneas al app.py principal
"""

# ==============================================================================
#           1. AÑADIR IMPORTS AL INICIO DEL APP.PY
# ==============================================================================

# Añadir después de los imports existentes:
import tempfile
import zipfile
import markdown
from flask import send_file

# ==============================================================================
#           2. MODIFICAR LA FUNCIÓN execute_gemini_bot EN bots/gemini_army.py
# ==============================================================================

def execute_gemini_bot(bot_id, context, query, user_credits, user_id=None):
    """
    VERSIÓN MEJORADA - Añadir user_id parameter y auto-save documents
    """
    
    if bot_id not in GEMINI_ARMY:
        return {
            "error": "Bot no encontrado",
            "available_bots": list(GEMINI_ARMY.keys())
        }
    
    bot = GEMINI_ARMY[bot_id]
    
    # Verificar créditos suficientes
    if user_credits < bot["credit_cost"]:
        return {
            "error": "insufficient_credits",
            "required": bot["credit_cost"],
            "available": user_credits,
            "upsell": True
        }
    
    try:
        # Preparar el prompt con contexto
        final_prompt = format_bot_prompt(bot["prompt"], context, query)
        
        # Configurar el modelo Gemini
        generation_config = {
            "temperature": 0.7,
            "top_p": 0.95,
            "top_k": 40,
            "max_output_tokens": 4000,
        }
        
        model = genai.GenerativeModel(
            model_name="gemini-2.0-flash",
            generation_config=generation_config
        )
        
        # Generar respuesta
        start_time = time.time()
        response = model.generate_content(final_prompt)
        processing_time = time.time() - start_time
        
        # ✅ NUEVA LÍNEA: Procesamiento mejorado con auto-save
        if user_id:
            processed_response = enhanced_process_bot_response(
                response.text, 
                bot.get("output_format", "text"),
                bot_id,
                user_id,
                context
            )
        else:
            processed_response = process_bot_response(response.text, bot.get("output_format", "text"))
        
        # Retornar respuesta estructurada
        return {
            "success": True,
            "bot_id": bot_id,
            "bot_name": bot["name"],
            "bot_description": bot["description"],
            "category": bot["category"],
            "response": processed_response,
            "raw_response": response.text,
            "processing_time": round(processing_time, 2),
            "credits_charged": bot["credit_cost"],
            "output_format": bot.get("output_format", "text"),
            "functions_available": bot.get("functions", []),
            "suggested_next_bots": get_suggested_next_bots(bot_id, context),
            "timestamp": datetime.now().isoformat(),
            
            # ✅ NUEVA INFORMACIÓN DE DOCUMENTO (si se guardó)
            "document_info": {
                "saved": processed_response.get("document_saved", False),
                "document_id": processed_response.get("document_id"),
                "title": processed_response.get("document_title"),
                "download_url": processed_response.get("download_url"),
                "view_url": processed_response.get("view_url")
            } if processed_response.get("document_saved") else None
        }
        
    except Exception as e:
        return {
            "error": f"Error ejecutando {bot['name']}: {str(e)}",
            "bot_id": bot_id,
            "bot_name": bot["name"],
            "retry_available": True,
            "timestamp": datetime.now().isoformat()
        }

# ==============================================================================
#           3. MODIFICAR EL ENDPOINT /chat/bot EN APP.PY
# ==============================================================================

@app.route('/chat/bot', methods=['POST'])
@require_auth
def chat_with_bot(user):
    """Chat con sistema de 60 bots - VERSIÓN MEJORADA"""
    try:
        data = request.json
        user_input = data.get('message', '')
        context = data.get('context', {})
        
        if not user_input:
            return jsonify({"error": "Message is required"}), 400
        
        # Añadir contexto del usuario
        user_context = {
            **context,
            "user_id": user['id'],
            "user_plan": user['plan'],
            "user_credits": user['credits_balance'],
            "neural_memory": get_neural_memory(user['id'])
        }
        
        # ✅ CAMBIO: Procesar con bot manager INCLUYENDO user_id
        bot_manager = BotManager()
        result = bot_manager.process_user_request(user_input, user_context, user['id'])
        
        # ✅ CAMBIO: Añadir información de documentos generados
        if result.get("success") and result.get("document_info"):
            result["message"] = "✅ Respuesta generada y documento guardado automáticamente"
            result["actions_available"] = [
                {
                    "type": "view_document",
                    "label": "Ver Documento",
                    "url": result["document_info"]["view_url"]
                },
                {
                    "type": "download_document", 
                    "label": "Descargar",
                    "url": result["document_info"]["download_url"]
                },
                {
                    "type": "view_all_documents",
                    "label": "Ver Todos mis Documentos",
                    "url": "/documents"
                }
            ]
        
        return jsonify(result)
        