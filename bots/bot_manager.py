from typing import Dict, Any, List, Optional
import google.generativeai as genai
from .gemini_army import BOT_PROMPTS, BOT_CATEGORIES

class BotManager:
    def __init__(self, api_key: str):
        """Initialize BotManager with Gemini API key."""
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel('gemini-pro')
        self.bot_prompts = BOT_PROMPTS
        self.categories = BOT_CATEGORIES

    def route_to_bot(self, user_input: str, context: Dict[str, Any]) -> str:
        """Route user input to the most appropriate bot."""
        routing_prompt = f"""
        Based on the following user input and context, determine which bot would be most appropriate to handle this request.
        User Input: {user_input}
        Context: {context}
        
        Available Categories:
        {self.categories}
        
        Return only the bot name that would be most appropriate.
        """
        
        response = self.model.generate_content(routing_prompt)
        selected_bot = response.text.strip()
        
        if selected_bot not in self.bot_prompts:
            return "general_assistant"  # Default to general assistant if routing fails
            
        return selected_bot

    def get_bot_response(self, bot_name: str, user_input: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Get response from specified bot."""
        if bot_name not in self.bot_prompts:
            return {
                "error": "Invalid bot name",
                "message": "The specified bot does not exist."
            }
            
        prompt = self.bot_prompts[bot_name]
        full_prompt = f"{prompt}\n\nUser Input: {user_input}\nContext: {context}"
        
        try:
            response = self.model.generate_content(full_prompt)
            return {
                "bot": bot_name,
                "response": response.text,
                "metadata": {
                    "category": self.get_bot_category(bot_name),
                    "suggested_next_bots": self.get_suggested_next_bots(bot_name, user_input)
                }
            }
        except Exception as e:
            return {
                "error": str(e),
                "message": "Failed to generate response"
            }

    def get_bot_category(self, bot_name: str) -> str:
        """Get category for a specific bot."""
        for category, bots in self.categories.items():
            if bot_name in bots:
                return category
        return "general"

    def get_suggested_next_bots(self, bot_name: str, user_input: str) -> List[str]:
        """Get suggested next bots based on current bot and user input."""
        suggestion_prompt = f"""
        Based on the current bot ({bot_name}) and user input ({user_input}),
        suggest the next 2-3 most relevant bots that could help the user.
        
        Available bots:
        {self.bot_prompts.keys()}
        
        Return only the bot names, one per line.
        """
        
        try:
            response = self.model.generate_content(suggestion_prompt)
            suggested_bots = [bot.strip() for bot in response.text.split('\n') if bot.strip()]
            return suggested_bots[:3]  # Return top 3 suggestions
        except:
            return []

    def get_available_bots(self) -> Dict[str, List[str]]:
        """Get list of all available bots by category."""
        return self.categories 