# CyberGuard: AI-powered Cybersecurity Assistant

CyberGuard is an AI-powered cybersecurity assistant built for Emerald Bank, featuring threat detection, prevention, and user education. The application can analyze URLs for security threats and answer cybersecurity-related questions.

## Features

- **URL Security Analysis**: Analyzes URLs for potential security threats and provides risk assessments
- **Cybersecurity Education**: Answers questions about topics like phishing, malware, password security, and more
- **No API Key Required**: Uses a built-in rule-based AI system that doesn't require any external API keys
- **Custom Branding**: Features custom Emerald Bank branding with burnt orange, yellow, and black color theme

## Project Structure

```
cyberguard/
├── app.py                      # Main Streamlit application
├── local_ai_assistant.py       # Rule-based AI assistant for cybersecurity questions
├── enhanced_url_analyzer.py    # URL security analysis engine
├── utils.py                    # Utility functions for the application
├── styles.py                   # Custom styling for the Streamlit interface
└── assets/                     # Contains logos and images
    └── updated_cyberguard_logo.svg    # CyberGuard logo
```

## Requirements

- Python 3.8+
- Streamlit
- BeautifulSoup4
- Requests
- TLDExtract

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd cyberguard
```

2. Install the required dependencies:
```bash
pip install streamlit beautifulsoup4 requests tldextract
```

## Usage

Run the Streamlit application:
```bash
streamlit run app.py
```

The application will be available at `http://localhost:8501` in your web browser.

## Deployment

The application can be deployed to Streamlit Sharing, Heroku, or any platform that supports Python web applications.

For Streamlit Sharing:
1. Push your code to a GitHub repository
2. Log in to [Streamlit Sharing](https://streamlit.io/sharing)
3. Create a new app and connect it to your GitHub repository

## Team Members

- Zubair Akhtar
- Anaika Rodrigues
- Mohammed Ateeq
- Joel Thomas
- Mohammed Nazeer
- Sarath PM

## License

This project is proprietary and confidential, developed exclusively for Emerald Bank.