import os
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
import requests
import json

# Configuration
TELEGRAM_BOT_TOKEN = "8238388865:AAHT-_mUbtwGB2OqPTgTTjoT7OBLW-lTxPI"
GROQ_API_KEY = "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"
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"

# Groq API function
def get_groq_response(user_message):
    """Send message to Groq API and get AI response"""
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": "llama-3.1-8b-instant",  # Using a reliable model name
        "messages": [
            {
                "role": "user",
                "content": user_message
            }
        ],
        "temperature": 0.7,
        "max_tokens": 1024,
        "top_p": 1,
        "stream": False
    }
    
    try:
        response = requests.post(GROQ_API_URL, headers=headers, json=payload, timeout=30)
        
        # Debug: Print response details
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text[:200]}")  # Print first 200 chars
        
        response.raise_for_status()
        
        data = response.json()
        ai_response = data['choices'][0]['message']['content']
        return ai_response
    
    except requests.exceptions.RequestException as e:
        error_msg = f"Error connecting to AI: {str(e)}"
        if hasattr(e, 'response') and e.response is not None:
            try:
                error_details = e.response.json()
                error_msg += f"\nDetails: {error_details}"
            except:
                error_msg += f"\nResponse: {e.response.text[:200]}"
        print(error_msg)  # Log to console
        return "Sorry, I'm having trouble connecting to the AI service. Please try again later."
    except (KeyError, IndexError) as e:
        error_msg = f"Error parsing AI response: {str(e)}"
        print(error_msg)
        return "Sorry, I received an unexpected response from the AI service."

# Telegram bot handlers
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Send welcome message when /start command is issued"""
    welcome_text = (
        "👋 Hello! I'm an AI-powered bot using Groq API.\n\n"
        "Just send me any message and I'll respond with AI-generated answers!\n\n"
        "Commands:\n"
        "/start - Show this welcome message\n"
        "/help - Get help information"
    )
    await update.message.reply_text(welcome_text)

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Send help message when /help command is issued"""
    help_text = (
        "🤖 How to use this bot:\n\n"
        "1. Simply type any question or message\n"
        "2. I'll process it using Groq AI\n"
        "3. You'll get an intelligent response!\n\n"
        "Examples:\n"
        "• 'Explain quantum physics simply'\n"
        "• 'Write a poem about coding'\n"
        "• 'What's the capital of France?'\n\n"
        "Feel free to ask me anything!"
    )
    await update.message.reply_text(help_text)

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle incoming messages and respond with AI"""
    user_message = update.message.text
    user_name = update.effective_user.first_name
    
    # Send typing indicator
    await update.message.chat.send_action(action="typing")
    
    # Get AI response from Groq
    ai_response = get_groq_response(user_message)
    
    # Send response back to user
    await update.message.reply_text(ai_response)

async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Log errors"""
    print(f'Update {update} caused error {context.error}')

def main():
    """Start the bot"""
    # Create application
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
    
    # Add handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    application.add_error_handler(error_handler)
    
    # Start the bot
    print("Bot is running...")
    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == '__main__':
    main()