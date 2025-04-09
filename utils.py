import re
import streamlit as st

def classify_query(user_input):
    """
    Classify user input as URL analysis request or educational query.
    
    Args:
        user_input: The user's input text
    
    Returns:
        "URL_ANALYSIS" if the input appears to be a URL, "EDUCATIONAL_QUERY" otherwise
    """
    # Simple URL pattern matching
    url_pattern = re.compile(
        r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    )
    
    if url_pattern.match(user_input):
        return "URL_ANALYSIS"
    else:
        return "EDUCATIONAL_QUERY"

def is_valid_url(url):
    """
    Check if a string is a valid URL.
    
    Args:
        url: The URL string to check
    
    Returns:
        True if valid URL, False otherwise
    """
    url_pattern = re.compile(
        r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    )
    
    return bool(url_pattern.match(url))

def load_svg(file_path):
    """
    Load an SVG file and return its contents.
    
    Args:
        file_path: Path to the SVG file
    
    Returns:
        SVG content as a string
    """
    try:
        with open(file_path, 'r') as f:
            return f.read()
    except FileNotFoundError:
        # Return a placeholder SVG for CyberGuard logo if file not found
        return """
        <svg width="60" height="60" viewBox="0 0 200 200" xmlns="http://www.w3.org/2000/svg">
            <polygon points="100,10 40,50 40,150 100,190 160,150 160,50" fill="#282828" stroke="#FF8C00" stroke-width="8"/>
            <path d="M70,80 L130,80 L130,120 L100,140 L70,120 Z" fill="#FF8C00"/>
            <circle cx="100" cy="60" r="15" fill="#FFD700"/>
        </svg>
        """

def add_message(role, content):
    """
    Add a message to the conversation history.
    
    Args:
        role: The role of the message sender ("user" or "assistant")
        content: The message content
    """
    st.session_state.messages.append({"role": role, "content": content})

def get_chat_message_container_style(is_user=True):
    """
    Get the styling for a chat message container.
    
    Args:
        is_user: True if the message is from the user, False if from the assistant
    
    Returns:
        CSS class name for the message container
    """
    return "user-message" if is_user else "assistant-message"
