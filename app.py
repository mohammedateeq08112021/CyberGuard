import streamlit as st
import os
from local_ai_assistant import LocalAIAssistant
from enhanced_url_analyzer import analyze_url
from utils import classify_query, load_svg, add_message, get_chat_message_container_style
from styles import apply_custom_styles, BURNT_ORANGE, YELLOW, BLACK

# Initialize the local AI assistant
local_ai = LocalAIAssistant()

# Page configuration
st.set_page_config(
    page_title="CyberGuard - AI Assistant for Emerald Bank",
    page_icon="assets/updated_cyberguard_logo.svg",
    layout="wide"
)

# Apply custom styling
apply_custom_styles()

def main():
    # Initialize session state for messages if it doesn't exist
    if "messages" not in st.session_state:
        st.session_state.messages = []
    
    # Get the CyberGuard logo and display in the sidebar
    cyberguard_logo = load_svg("assets/updated_cyberguard_logo.svg")
    
    # Sidebar with logo and configuration
    with st.sidebar:
        st.markdown(f'<div style="display: flex; justify-content: center;">{cyberguard_logo}</div>', unsafe_allow_html=True)
        st.markdown("<h2 style='text-align: center; color: #FF8C00;'>CyberGuard</h2>", unsafe_allow_html=True)
        st.markdown("<h4 style='text-align: center; color: #FFD700;'>AI Assistant for Emerald Bank</h4>", unsafe_allow_html=True)
        
        st.divider()
        
        # Streaming response option
        use_streaming = st.checkbox("Use streaming responses", value=True)
        
        st.markdown(f"""
        <div class='security-alert' style='margin: 15px 0;'>
            <p><span style='color: {BURNT_ORANGE}; font-weight: bold;'>Free AI Mode</span> - Using built-in cybersecurity AI assistant that doesn't require an API key.</p>
        </div>
        """, unsafe_allow_html=True)
        
        st.divider()
        
        # Team information
        st.markdown("### Team Members")
        team_members = [
            "Zubair Akhtar",
            "Anaika Rodrigues",
            "Mohammed Ateeq",
            "Joel Thomas",
            "Mohammed Nazeer",
            "Sarath PM"
        ]
        for member in team_members:
            st.markdown(f"- {member}")
        
        # Clear chat button
        if st.button("Clear Chat"):
            st.session_state.messages = []
            st.rerun()
    
    # Main content area
    st.markdown(
        f"""
        <div style='display: flex; align-items: center; margin-bottom: 20px; background-color: #1E1E1E; padding: 15px; border-radius: 10px; border-bottom: 3px solid {BURNT_ORANGE};'>
            <div style='margin-right: 15px;'>{cyberguard_logo}</div>
            <div>
                <h1 style='margin: 0; color: {BURNT_ORANGE};'>CyberGuard</h1>
                <h4 style='margin: 5px 0 0 0; color: {YELLOW};'>AI-powered Security Assistant for Emerald Bank</h4>
            </div>
        </div>
        """, 
        unsafe_allow_html=True
    )
    
    st.markdown(f"""
    <div class='security-alert' style='margin-bottom: 20px;'>
        <p><span style='color: {BURNT_ORANGE}; font-weight: bold;'>Welcome to CyberGuard</span> - your AI-powered cybersecurity assistant. 
        Ask me any cybersecurity questions or paste a URL to analyze its security risks.</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Display chat messages
    for message in st.session_state.messages:
        avatar = None
        if message["role"] == "assistant":
            avatar = load_svg("assets/updated_cyberguard_logo.svg")
        with st.chat_message(message["role"], avatar=avatar):
            st.markdown(message["content"])
    
    # Chat input
    if user_input := st.chat_input("Type your question or enter a URL to analyze..."):
        # Add user message to chat
        add_message("user", user_input)
        
        # Display user message
        with st.chat_message("user"):
            st.markdown(user_input)
        
        # Classify the query
        query_type = classify_query(user_input)
        
        # Process based on query type
        with st.chat_message("assistant", avatar=load_svg("assets/updated_cyberguard_logo.svg")):
            if query_type == "URL_ANALYSIS":
                # Process URL analysis
                with st.spinner("Analyzing URL for security threats..."):
                    analysis_result = analyze_url(user_input)
                    st.markdown(analysis_result)
                    add_message("assistant", analysis_result)
            else:
                # Process educational query with local AI
                previous_messages = [msg for msg in st.session_state.messages[:-1] if msg["role"] == "user"]
                conversation_history = [msg["content"] for msg in previous_messages]
                
                if use_streaming:
                    response_placeholder = st.empty()
                    full_response = local_ai.stream_response(
                        user_input, 
                        conversation_history,
                        response_placeholder
                    )
                    add_message("assistant", full_response)
                else:
                    with st.spinner("Thinking..."):
                        response = local_ai.get_response(user_input, conversation_history)
                        st.markdown(response)
                        add_message("assistant", response)

if __name__ == "__main__":
    main()
