# -*- coding: utf-8 -*-

"""
0Bullshit Backend v2.0 - Sistema de Memoria Inteligente de Proyecto
Análisis completo del contexto, progreso y recomendaciones de siguientes pasos
"""

import json
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from sqlalchemy import text
import pandas as pd

# ==============================================================================
#           PROJECT CONTEXT ANALYZER
# ==============================================================================

class ProjectContextAnalyzer:
    """
    Analizador inteligente que comprende el estado completo del proyecto del usuario
    y sugiere los próximos pasos más lógicos
    """
    
    def __init__(self, user_id: str, engine):
        self.user_id = user_id
        self.engine = engine
        self.project_state = {}
        self.user_plan = None
        
    def analyze_complete_context(self) -> Dict:
        """
        Análisis completo del contexto del proyecto
        """
        try:
            # 1. Obtener información básica del usuario
            user_info = self._get_user_info()
            
            # 2. Analizar documentos generados
            documents_analysis = self._analyze_generated_documents()
            
            # 3. Analizar historial de chats
            chat_history_analysis = self._analyze_chat_history()
            
            # 4. Analizar entidades guardadas
            entities_analysis = self._analyze_saved_entities()
            
            # 5. Extraer contexto de startup
            startup_context = self._extract_startup_context()
            
            # 6. Determinar fase del proyecto
            project_phase = self._determine_project_phase()
            
            # 7. Generar recomendaciones inteligentes
            recommendations = self._generate_smart_recommendations()
            
            return {
                "user_info": user_info,
                "project_phase": project_phase,
                "startup_context": startup_context,
                "progress_analysis": {
                    "documents": documents_analysis,
                    "chat_history": chat_history_analysis,
                    "saved_entities": entities_analysis
                },
                "recommendations": recommendations,
                "next_steps": self._prioritize_next_steps(),
                "readiness_scores": self._calculate_readiness_scores(),
                "analysis_timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            print(f"❌ Error in context analysis: {e}")
            return {"error": "Could not analyze project context"}

    def _get_user_info(self) -> Dict:
        """Obtiene información básica del usuario"""
        try:
            query = """
            SELECT u.id, u.plan, u.credits_balance, u.created_at,
                   COUNT(DISTINCT ni.id) as total_interactions,
                   COUNT(DISTINCT gd.id) as total_documents,
                   COUNT(DISTINCT se.id) as total_saved_entities
            FROM users u
            LEFT JOIN neural_interactions ni ON u.id = ni.user_id
            LEFT JOIN generated_documents gd ON u.id = gd.user_id  
            LEFT JOIN saved_entities se ON u.id = se.user_id
            WHERE u.id = %s
            GROUP BY u.id, u.plan, u.credits_balance, u.created_at
            """
            
            result = pd.read_sql(query, self.engine, params=[self.user_id])
            
            if result.empty:
                return {}
            
            user_data = result.iloc[0]
            self.user_plan = user_data['plan']
            
            return {
                "user_id": user_data['id'],
                "plan": user_data['plan'],
                "credits_balance": user_data['credits_balance'],
                "account_age_days": (datetime.now() - user_data['created_at']).days,
                "total_interactions": user_data['total_interactions'],
                "total_documents": user_data['total_documents'],
                "total_saved_entities": user_data['total_saved_entities'],
                "engagement_level": self._calculate_engagement_level(user_data)
            }
            
        except Exception as e:
            print(f"❌ Error getting user info: {e}")
            return {}

    def _analyze_generated_documents(self) -> Dict:
        """Analiza documentos generados para entender el progreso"""
        try:
            query = """
            SELECT document_type, title, bot_used, created_at, metadata
            FROM generated_documents
            WHERE user_id = %s
            ORDER BY created_at DESC
            """
            
            result = pd.read_sql(query, self.engine, params=[self.user_id])
            
            if result.empty:
                return {"total": 0, "types": {}, "has_essential": {}}
            
            # Contar tipos de documentos
            doc_types = result['document_type'].value_counts().to_dict()
            
            # Verificar documentos esenciales
            essential_docs = {
                "has_pitch_deck": "pitch_deck" in doc_types,
                "has_business_plan": "business_plan" in doc_types,
                "has_financial_model": "financial_model" in doc_types,
                "has_market_analysis": "market_analysis" in doc_types,
                "has_strategy_document": "strategy_document" in doc_types,
                "has_brand_strategy": "brand_strategy" in doc_types,
                "has_legal_documents": "legal_document" in doc_types
            }
            
            # Analizar bots más usados
            bot_usage = result['bot_used'].value_counts().head(5).to_dict()
            
            # Documentos recientes (últimos 7 días)
            recent_docs = result[
                result['created_at'] > (datetime.now() - timedelta(days=7))
            ]
            
            return {
                "total": len(result),
                "types": doc_types,
                "essential_documents": essential_docs,
                "completion_score": sum(essential_docs.values()) / len(essential_docs) * 100,
                "most_used_bots": bot_usage,
                "recent_activity": len(recent_docs),
                "last_document_date": result.iloc[0]['created_at'].isoformat() if len(result) > 0 else None
            }
            
        except Exception as e:
            print(f"❌ Error analyzing documents: {e}")
            return {"total": 0, "error": str(e)}

    def _analyze_chat_history(self) -> Dict:
        """Analiza historial de chats para entender patrones e intenciones"""
        try:
            query = """
            SELECT bot_used, user_input, created_at
            FROM neural_interactions
            WHERE user_id = %s
            ORDER BY created_at DESC
            LIMIT 100
            """
            
            result = pd.read_sql(query, self.engine, params=[self.user_id])
            
            if result.empty:
                return {"total": 0, "patterns": {}}
            
            # Analizar patrones de uso
            bot_frequency = result['bot_used'].value_counts().to_dict()
            
            # Analizar intenciones en los últimos chats
            recent_inputs = result.head(20)['user_input'].tolist()
            intentions = self._extract_user_intentions(recent_inputs)
            
            # Analizar frecuencia de uso
            dates = pd.to_datetime(result['created_at'])
            daily_usage = dates.dt.date.value_counts().head(7).to_dict()
            
            # Detectar focus areas
            focus_areas = self._detect_focus_areas(result['user_input'].tolist())
            
            return {
                "total_interactions": len(result),
                "bot_frequency": bot_frequency,
                "detected_intentions": intentions,
                "daily_usage_pattern": {str(k): v for k, v in daily_usage.items()},
                "focus_areas": focus_areas,
                "activity_level": self._calculate_activity_level(result),
                "last_interaction": result.iloc[0]['created_at'].isoformat() if len(result) > 0 else None
            }
            
        except Exception as e:
            print(f"❌ Error analyzing chat history: {e}")
            return {"total": 0, "error": str(e)}

    def _analyze_saved_entities(self) -> Dict:
        """Analiza entidades guardadas (inversores, empleados)"""
        try:
            query = """
            SELECT entity_type, sentiment, created_at, tags
            FROM saved_entities
            WHERE user_id = %s
            ORDER BY created_at DESC
            """
            
            result = pd.read_sql(query, self.engine, params=[self.user_id])
            
            if result.empty:
                return {"total": 0, "investors": 0, "employees": 0}
            
            # Contar por tipo
            by_type = result['entity_type'].value_counts().to_dict()
            
            # Analizar sentiment
            sentiment_analysis = result['sentiment'].value_counts().to_dict()
            
            # Inversores con sentiment positivo
            positive_investors = len(result[
                (result['entity_type'] == 'investor') & 
                (result['sentiment'] == 'like')
            ])
            
            # Empleados con sentiment positivo  
            positive_employees = len(result[
                (result['entity_type'] == 'employee') & 
                (result['sentiment'] == 'like')
            ])
            
            return {
                "total": len(result),
                "by_type": by_type,
                "sentiment_distribution": sentiment_analysis,
                "positive_investors": positive_investors,
                "positive_employees": positive_employees,
                "ready_for_outreach": positive_investors + positive_employees >= 5,
                "last_saved": result.iloc[0]['created_at'].isoformat() if len(result) > 0 else None
            }
            
        except Exception as e:
            print(f"❌ Error analyzing saved entities: {e}")
            return {"total": 0, "error": str(e)}

    def _extract_startup_context(self) -> Dict:
        """Extrae contexto completo de la startup desde todas las fuentes"""
        try:
            # Obtener memoria neuronal
            neural_memory = get_neural_memory(self.user_id)
            
            # Analizar documentos para extraer contexto
            doc_context = self._extract_context_from_documents()
            
            # Analizar chats para extraer contexto
            chat_context = self._extract_context_from_chats()
            
            # Combinar y consolidar contexto
            consolidated_context = {
                # Información básica
                "startup_name": self._extract_startup_name(),
                "industry": self._extract_industry(),
                "stage": self._extract_stage(),
                "location": self._extract_location(),
                "business_model": self._extract_business_model(),
                
                # Información financiera
                "funding_needed": self._extract_funding_amount(),
                "current_revenue": self._extract_revenue(),
                "team_size": self._extract_team_size(),
                
                # Contexto de mercado
                "target_market": self._extract_target_market(),
                "competitors": self._extract_competitors(),
                "value_proposition": self._extract_value_prop(),
                
                # Estado del proyecto
                "project_maturity": self._calculate_project_maturity(),
                "main_challenges": self._extract_challenges(),
                "immediate_needs": self._extract_immediate_needs()
            }
            
            return consolidated_context
            
        except Exception as e:
            print(f"❌ Error extracting startup context: {e}")
            return {}

    def _determine_project_phase(self) -> Dict:
        """Determina en qué fase está el proyecto"""
        try:
            docs_analysis = self._analyze_generated_documents()
            entities_analysis = self._analyze_saved_entities()
            
            # Definir fases del proyecto
            phases = {
                "ideation": {
                    "description": "Ideación y conceptualización inicial",
                    "requirements": ["basic_interactions"],
                    "next_step": "Crear documentos fundamentales"
                },
                "documentation": {
                    "description": "Creación de documentos fundamentales",
                    "requirements": ["pitch_deck", "business_plan_or_strategy"],
                    "next_step": "Buscar inversores y hacer networking"
                },
                "networking": {
                    "description": "Búsqueda de inversores y networking",
                    "requirements": ["essential_docs", "some_saved_entities"],
                    "next_step": "Preparar outreach personalizado"
                },
                "outreach_ready": {
                    "description": "Listo para outreach automatizado",
                    "requirements": ["complete_docs", "target_list", "templates"],
                    "next_step": "Ejecutar campañas de outreach"
                },
                "scaling": {
                    "description": "Escalando outreach y fundraising",
                    "requirements": ["active_campaigns", "investor_meetings"],
                    "next_step": "Optimizar y escalar procesos"
                }
            }
            
            # Determinar fase actual
            current_phase = self._calculate_current_phase(docs_analysis, entities_analysis)
            
            return {
                "current_phase": current_phase,
                "phase_info": phases.get(current_phase, {}),
                "progress_percentage": self._calculate_phase_progress(current_phase),
                "blocking_factors": self._identify_blocking_factors(),
                "phase_recommendations": self._get_phase_specific_recommendations(current_phase)
            }
            
        except Exception as e:
            print(f"❌ Error determining project phase: {e}")
            return {"current_phase": "unknown", "error": str(e)}

    def _generate_smart_recommendations(self) -> List[Dict]:
        """Genera recomendaciones inteligentes basadas en el análisis completo"""
        try:
            recommendations = []
            docs_analysis = self._analyze_generated_documents()
            entities_analysis = self._analyze_saved_entities()
            user_info = self._get_user_info()
            
            # 1. Recomendaciones basadas en documentos faltantes
            if not docs_analysis.get("essential_documents", {}).get("has_pitch_deck"):
                recommendations.append({
                    "type": "create_document",
                    "priority": "high",
                    "title": "Crear Pitch Deck",
                    "description": "No tienes un pitch deck. Es fundamental para presentar tu startup a inversores.",
                    "action": "chat_with_bot",
                    "bot_id": "pitch_deck_master",
                    "estimated_credits": 50,
                    "plan_required": "free"
                })
            
            if not docs_analysis.get("essential_documents", {}).get("has_financial_model"):
                recommendations.append({
                    "type": "create_document", 
                    "priority": "high",
                    "title": "Crear Modelo Financiero",
                    "description": "Un modelo financiero sólido es crucial para proyecciones y valoración.",
                    "action": "chat_with_bot",
                    "bot_id": "financial_modeler",
                    "estimated_credits": 50,
                    "plan_required": "free"
                })
            
            # 2. Recomendaciones basadas en plan y progreso
            if (user_info.get("plan") == "free" and 
                docs_analysis.get("completion_score", 0) > 60):
                recommendations.append({
                    "type": "upgrade_plan",
                    "priority": "medium", 
                    "title": "Upgrade a Growth Plan",
                    "description": "Tienes buenos documentos. Es hora de buscar inversores con búsqueda ML.",
                    "action": "upgrade_plan",
                    "target_plan": "growth",
                    "benefits": ["Búsqueda ML de inversores", "100k créditos de lanzamiento"],
                    "plan_required": "growth"
                })
            
            # 3. Recomendaciones basadas en entidades guardadas
            if (user_info.get("plan") in ["growth", "pro"] and 
                entities_analysis.get("positive_investors", 0) == 0):
                recommendations.append({
                    "type": "search_investors",
                    "priority": "high",
                    "title": "Buscar Inversores",
                    "description": "Tienes documentos listos. Busca inversores específicos para tu industria.",
                    "action": "search_investors",
                    "estimated_credits": 200,
                    "plan_required": "growth"
                })
            
            # 4. Recomendaciones de outreach
            if (user_info.get("plan") == "growth" and 
                entities_analysis.get("positive_investors", 0) >= 5):
                recommendations.append({
                    "type": "upgrade_plan",
                    "priority": "medium",
                    "title": "Upgrade a Pro Outreach",
                    "description": "Tienes inversores guardados. Automatiza el outreach con templates personalizados.",
                    "action": "upgrade_plan", 
                    "target_plan": "pro",
                    "benefits": ["Templates ilimitados", "Outreach automatizado", "1M créditos"],
                    "plan_required": "pro"
                })
            
            if (user_info.get("plan") == "pro" and 
                entities_analysis.get("total", 0) >= 10):
                recommendations.append({
                    "type": "start_outreach",
                    "priority": "high",
                    "title": "Iniciar Campañas de Outreach",
                    "description": "Todo está listo. Crea templates y lanza campañas automatizadas.",
                    "action": "create_outreach_campaign",
                    "estimated_credits": 500,
                    "plan_required": "pro"
                })
            
            # 5. Recomendaciones de contenido
            if not docs_analysis.get("essential_documents", {}).get("has_market_analysis"):
                recommendations.append({
                    "type": "create_document",
                    "priority": "medium",
                    "title": "Análisis de Mercado",
                    "description": "Un análisis de mercado fortalecerá tu estrategia y pitch.",
                    "action": "chat_with_bot",
                    "bot_id": "market_analyzer", 
                    "estimated_credits": 60,
                    "plan_required": "free"
                })
            
            # Ordenar por prioridad
            priority_order = {"high": 3, "medium": 2, "low": 1}
            recommendations.sort(key=lambda x: priority_order.get(x.get("priority", "low"), 1), reverse=True)
            
            return recommendations[:5]  # Top 5 recomendaciones
            
        except Exception as e:
            print(f"❌ Error generating recommendations: {e}")
            return []

    def _calculate_readiness_scores(self) -> Dict:
        """Calcula scores de preparación para diferentes acciones"""
        try:
            docs_analysis = self._analyze_generated_documents()
            entities_analysis = self._analyze_saved_entities()
            
            # Score para fundraising (0-100)
            fundraising_score = 0
            if docs_analysis.get("essential_documents", {}).get("has_pitch_deck"):
                fundraising_score += 30
            if docs_analysis.get("essential_documents", {}).get("has_financial_model"):
                fundraising_score += 25
            if docs_analysis.get("essential_documents", {}).get("has_market_analysis"):
                fundraising_score += 20
            if docs_analysis.get("essential_documents", {}).get("has_business_plan"):
                fundraising_score += 15
            if entities_analysis.get("positive_investors", 0) > 0:
                fundraising_score += 10
            
            # Score para outreach (0-100)
            outreach_score = 0
            if docs_analysis.get("completion_score", 0) > 50:
                outreach_score += 40
            if entities_analysis.get("positive_investors", 0) >= 5:
                outreach_score += 35
            if entities_analysis.get("positive_employees", 0) >= 3:
                outreach_score += 15
            if entities_analysis.get("total", 0) >= 10:
                outreach_score += 10
            
            # Score para scaling (0-100)
            scaling_score = min(fundraising_score + outreach_score - 50, 100)
            
            return {
                "fundraising_readiness": min(fundraising_score, 100),
                "outreach_readiness": min(outreach_score, 100),
                "scaling_readiness": max(scaling_score, 0),
                "overall_progress": (fundraising_score + outreach_score) / 2
            }
            
        except Exception as e:
            print(f"❌ Error calculating readiness scores: {e}")
            return {"fundraising_readiness": 0, "outreach_readiness": 0, "scaling_readiness": 0}

    # ==================== HELPER METHODS ====================
    
    def _extract_user_intentions(self, recent_inputs: List[str]) -> List[str]:
        """Extrae intenciones del usuario de inputs recientes"""
        intentions = []
        
        for input_text in recent_inputs:
            lower_input = input_text.lower()
            
            if any(word in lower_input for word in ["pitch deck", "presentación", "inversores"]):
                intentions.append("fundraising_preparation")
            if any(word in lower_input for word in ["buscar inversores", "encontrar VCs", "fundraising"]):
                intentions.append("investor_search")
            if any(word in lower_input for word in ["outreach", "contactar", "plantilla", "email"]):
                intentions.append("outreach_planning")
            if any(word in lower_input for word in ["análisis", "mercado", "competencia"]):
                intentions.append("market_research")
            if any(word in lower_input for word in ["modelo", "financiero", "valoración"]):
                intentions.append("financial_planning")
        
        return list(set(intentions))  # Remove duplicates

    def _detect_focus_areas(self, inputs: List[str]) -> Dict:
        """Detecta áreas de enfoque del usuario"""
        focus_keywords = {
            "product": ["producto", "feature", "desarrollo", "UX", "usuario"],
            "marketing": ["marketing", "contenido", "SEO", "brand", "marca"],
            "fundraising": ["inversión", "investor", "funding", "capital", "VC"],
            "strategy": ["estrategia", "mercado", "competencia", "análisis"],
            "operations": ["operaciones", "equipo", "hiring", "cultura"],
            "legal": ["legal", "contrato", "términos", "compliance"]
        }
        
        focus_scores = {}
        total_inputs = len(inputs)
        
        for area, keywords in focus_keywords.items():
            count = 0
            for input_text in inputs:
                if any(keyword in input_text.lower() for keyword in keywords):
                    count += 1
            focus_scores[area] = (count / total_inputs) * 100 if total_inputs > 0 else 0
        
        return focus_scores

    def _calculate_current_phase(self, docs_analysis: Dict, entities_analysis: Dict) -> str:
        """Calcula la fase actual del proyecto"""
        essential_docs = docs_analysis.get("essential_documents", {})
        has_pitch_deck = essential_docs.get("has_pitch_deck", False)
        has_any_strategy = (essential_docs.get("has_business_plan", False) or 
                           essential_docs.get("has_strategy_document", False))
        completion_score = docs_analysis.get("completion_score", 0)
        saved_entities = entities_analysis.get("total", 0)
        
        if completion_score < 20:
            return "ideation"
        elif not has_pitch_deck or not has_any_strategy:
            return "documentation"
        elif saved_entities < 5:
            return "networking"
        elif saved_entities >= 10 and completion_score > 70:
            return "outreach_ready"
        else:
            return "scaling"

    def _prioritize_next_steps(self) -> List[Dict]:
        """Prioriza los siguientes pasos más importantes"""
        recommendations = self._generate_smart_recommendations()
        
        # Convertir recomendaciones en next steps priorizados
        next_steps = []
        for rec in recommendations[:3]:  # Top 3
            next_steps.append({
                "step": rec.get("title", ""),
                "description": rec.get("description", ""),
                "priority": rec.get("priority", "medium"),
                "action_type": rec.get("action", ""),
                "estimated_credits": rec.get("estimated_credits", 0),
                "plan_required": rec.get("plan_required", "free")
            })
        
        return next_steps

    # Placeholder methods for extraction (implement based on your specific needs)
    def _extract_startup_name(self): return "Mi Startup"
    def _extract_industry(self): return "Technology"
    def _extract_stage(self): return "Seed"
    def _extract_location(self): return "Spain"
    def _extract_business_model(self): return "SaaS"
    def _extract_funding_amount(self): return "€500K"
    def _extract_revenue(self): return "€0"
    def _extract_team_size(self): return "2-5"
    def _extract_target_market(self): return "SMBs"
    def _extract_competitors(self): return []
    def _extract_value_prop(self): return "Efficiency solution"
    def _calculate_project_maturity(self): return "Early"
    def _extract_challenges(self): return ["Product-market fit"]
    def _extract_immediate_needs(self): return ["Funding"]
    def _calculate_engagement_level(self, user_data): return "Medium"
    def _calculate_activity_level(self, interactions): return "Active"
    def _calculate_phase_progress(self, phase): return 60
    def _identify_blocking_factors(self): return []
    def _get_phase_specific_recommendations(self, phase): return []
    def _extract_context_from_documents(self): return {}
    def _extract_context_from_chats(self): return {}

# ==============================================================================
#           API ENDPOINT PARA ANÁLISIS DE CONTEXTO
# ==============================================================================

@app.route('/project/context-analysis', methods=['GET'])
@require_auth
def get_project_context_analysis(user):
    """
    Endpoint que devuelve análisis completo del contexto del proyecto
    y sugerencias inteligentes de siguientes pasos
    """
    try:
        analyzer = ProjectContextAnalyzer(user['id'], engine)
        analysis = analyzer.analyze_complete_context()
        
        return jsonify({
            "success": True,
            "user_id": user['id'],
            "analysis": analysis,
            "generated_at": datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"❌ Error in context analysis: {e}")
        return jsonify({"error": "Could not analyze project context"}), 500

@app.route('/project/next-steps', methods=['GET'])
@require_auth
def get_next_steps(user):
    """
    Endpoint específico para obtener solo los próximos pasos recomendados
    """
    try:
        analyzer = ProjectContextAnalyzer(user['id'], engine)
        analysis = analyzer.analyze_complete_context()
        
        return jsonify({
            "next_steps": analysis.get("next_steps", []),
            "readiness_scores": analysis.get("readiness_scores", {}),
            "current_phase": analysis.get("project_phase", {}).get("current_phase", "unknown"),
            "recommendations": analysis.get("recommendations", [])[:3]  # Top 3
        })
        
    except Exception as e:
        print(f"❌ Error getting next steps: {e}")
        return jsonify({"error": "Could not get next steps"}), 500

@app.route('/project/smart-suggestions', methods=['POST'])
@require_auth
def get_smart_suggestions(user):
    """
    Endpoint que da sugerencias basadas en contexto específico
    """
    try:
        data = request.json
        current_action = data.get('current_action', '')
        context = data.get('context', {})
        
        analyzer = ProjectContextAnalyzer(user['id'], engine)
        analysis = analyzer.analyze_complete_context()
        
        # Generar sugerencias específicas para la acción actual
        suggestions = []
        
        if current_action == 'chat_completed':
            # Usuario acaba de completar un chat
            last_bot = context.get('bot_used', '')
            
            if last_bot == 'pitch_deck_master':
                suggestions = [
                    {
                        "type": "next_bot",
                        "title": "Crear Modelo Financiero",
                        "description": "Complementa tu pitch deck con proyecciones financieras sólidas",
                        "bot_id": "financial_modeler",
                        "priority": "high"
                    },
                    {
                        "type": "upgrade_plan", 
                        "title": "Buscar Inversores",
                        "description": "Tu pitch está listo. Encuentra inversores específicos con Growth plan",
                        "target_plan": "growth",
                        "priority": "medium"
                    }
                ]
            
            elif last_bot == 'financial_modeler':
                readiness = analysis.get("readiness_scores", {})
                if readiness.get("fundraising_readiness", 0) > 70:
                    suggestions = [
                        {
                            "type": "search_investors",
                            "title": "Buscar Inversores Ahora",
                            "description": "Tienes documentos sólidos. Busca inversores específicos",
                            "action": "search_investors",
                            "priority":