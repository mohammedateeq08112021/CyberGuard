import streamlit as st

# Define color constants
BURNT_ORANGE = "#FF8C00"  # Burnt orange
YELLOW = "#FFD700"       # Yellow
BLACK = "#1E1E1E"        # Black

def apply_custom_styles():
    """Apply custom styling to the Streamlit app"""
    
    # Apply custom CSS styles
    st.markdown("""
    <style>
    /* Custom CyberGuard styles */
    
    /* Button styling */
    .stButton>button {
        background-color: #FF8C00 !important;
        color: white !important;
        border: none !important;
        border-radius: 4px !important;
        padding: 0.5rem 1rem !important;
        transition: background-color 0.3s !important;
    }
    
    .stButton>button:hover {
        background-color: #E07800 !important;
    }
    
    /* Chat message styling */
    .user-message {
        background-color: #292929;
        border-radius: 8px;
        padding: 10px 15px;
        margin-bottom: 10px;
        border-right: 3px solid #FFD700;
    }
    
    .assistant-message {
        background-color: #282828;
        border-radius: 8px;
        padding: 10px 15px;
        margin-bottom: 10px;
        border-left: 3px solid #FF8C00;
    }
    
    /* Sidebar styling */
    .css-1d391kg {
        background-color: #1E1E1E;
    }
    
    /* Custom headers */
    h1, h2, h3 {
        color: #FF8C00 !important;
    }
    
    /* Custom links */
    a {
        color: #FFD700 !important;
    }
    
    /* Customize the chat input box */
    .stChatInputContainer {
        border-color: #FF8C00 !important;
    }
    
    /* Risk level styling */
    .risk-low {
        color: #4CAF50;
        font-weight: bold;
    }
    
    .risk-medium {
        color: #FF9800;
        font-weight: bold;
    }
    
    .risk-high {
        color: #F44336;
        font-weight: bold;
    }
    
    .risk-critical {
        color: #9C27B0;
        font-weight: bold;
    }
    
    /* Custom divider */
    hr {
        border-color: #FF8C00 !important;
    }
    
    /* Highlight important text */
    .highlight {
        background-color: #FF8C00;
        color: #1E1E1E;
        padding: 2px 5px;
        border-radius: 3px;
    }
    
    /* Custom alert boxes */
    .security-alert {
        background-color: #1E1E1E;
        border-left: 5px solid #FF8C00;
        padding: 10px 15px;
        margin: 10px 0;
        border-radius: 0 5px 5px 0;
    }
    
    /* Enhance chat message avatar */
    .stChatMessageAvatar {
        background-color: #FF8C00 !important;
    }
    </style>
    """, unsafe_allow_html=True)
