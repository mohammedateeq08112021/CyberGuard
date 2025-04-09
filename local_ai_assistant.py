"""
Simple rule-based AI assistant for CyberGuard that doesn't require an API key.
This provides basic cybersecurity information and advice.
"""

import random
import re

class LocalAIAssistant:
    def __init__(self):
        # Define common cybersecurity topics and responses
        self.topics = {
            "phishing": [
                "Phishing is a type of cyber attack where attackers disguise themselves as trustworthy entities to steal sensitive information like passwords and credit card details. Here are some tips to avoid phishing:\n\n"
                "- Check email sender addresses carefully\n"
                "- Don't click on suspicious links in emails or messages\n"
                "- Look for spelling errors or unusual requests\n"
                "- Verify requests for personal information through official channels\n"
                "- Use multi-factor authentication when possible",
                
                "Phishing attacks typically try to trick you into revealing personal information by pretending to be a legitimate organization. Protection strategies include:\n\n"
                "- Be suspicious of urgent requests for personal information\n"
                "- Hover over links to see the actual URL before clicking\n"
                "- Use anti-phishing browser extensions\n"
                "- Keep your browser and security software updated\n"
                "- Report suspected phishing attempts to your IT department or the spoofed organization"
            ],
            
            "password": [
                "Strong password practices are essential for cybersecurity. Here are some recommendations:\n\n"
                "- Use a unique password for each account\n"
                "- Create passwords that are at least 12 characters long\n"
                "- Include uppercase letters, lowercase letters, numbers, and special characters\n"
                "- Consider using a password manager to generate and store complex passwords\n"
                "- Change passwords regularly, especially for sensitive accounts",
                
                "Password security is your first line of defense. Best practices include:\n\n"
                "- Never share your passwords with others\n"
                "- Avoid using personal information in your passwords\n"
                "- Don't store passwords in plain text files or notes\n"
                "- Use multi-factor authentication whenever possible\n"
                "- Consider using passphrases that are long but memorable"
            ],
            
            "malware": [
                "Malware (malicious software) includes viruses, worms, trojans, ransomware, and spyware. To protect yourself:\n\n"
                "- Keep your operating system and applications updated\n"
                "- Use reputable antivirus and anti-malware software\n"
                "- Be careful about downloading files or clicking on links\n"
                "- Scan email attachments before opening them\n"
                "- Regularly back up your important data",
                
                "Malware can infect your devices and steal information or cause damage. Prevention tips:\n\n"
                "- Only download software from official sources\n"
                "- Be wary of unexpected email attachments, even from known senders\n"
                "- Use a firewall to block unauthorized access\n"
                "- Disable autorun features for removable media\n"
                "- Consider using script blockers in your web browser"
            ],
            
            "ransomware": [
                "Ransomware is malware that encrypts your files and demands payment for the decryption key. Protection strategies include:\n\n"
                "- Keep regular backups of important data on disconnected storage\n"
                "- Keep all software updated with security patches\n"
                "- Use email filtering and be cautious of attachments\n"
                "- Implement network segmentation to limit spread\n"
                "- Have an incident response plan ready",
                
                "Ransomware attacks can be devastating to individuals and organizations. To stay safe:\n\n"
                "- Train yourself to recognize suspicious emails and websites\n"
                "- Use application whitelisting to prevent unauthorized programs from running\n"
                "- Disable macros in Microsoft Office documents\n"
                "- Consider using ransomware-specific protection tools\n"
                "- If infected, disconnect from networks immediately to prevent spread"
            ],
            
            "social engineering": [
                "Social engineering is the psychological manipulation of people to get them to divulge confidential information or perform actions. Prevention tips:\n\n"
                "- Verify the identity of anyone requesting information\n"
                "- Be suspicious of unexpected contacts or unusual requests\n"
                "- Don't provide personal information in response to unsolicited requests\n"
                "- Be aware that scammers create a sense of urgency to bypass your critical thinking\n"
                "- Trust your instincts if something feels wrong",
                
                "Social engineering attacks exploit human psychology rather than technical vulnerabilities. Stay protected by:\n\n"
                "- Establishing verification procedures for sensitive requests\n"
                "- Being cautious about information you share on social media\n"
                "- Knowing the common signs of manipulation (urgency, fear, curiosity)\n"
                "- Taking time to verify requests through official channels\n"
                "- Reporting suspected social engineering attempts"
            ],
            
            "vpn": [
                "A Virtual Private Network (VPN) encrypts your internet connection and protects your privacy online. Benefits include:\n\n"
                "- Encrypting your internet traffic from potential eavesdroppers\n"
                "- Hiding your IP address and location\n"
                "- Allowing secure access to public Wi-Fi networks\n"
                "- Bypassing geographical restrictions on content\n"
                "- Preventing some forms of tracking and targeted advertising",
                
                "Using a VPN is a good privacy practice, especially on public networks. Important considerations:\n\n"
                "- Choose a reputable VPN provider with a no-logs policy\n"
                "- Ensure the VPN uses strong encryption protocols\n"
                "- Be aware that a VPN doesn't make you completely anonymous\n"
                "- Some services may not work properly through a VPN\n"
                "- Free VPNs may collect and sell your data, so research carefully"
            ],
            
            "two-factor authentication": [
                "Two-factor authentication (2FA) or multi-factor authentication (MFA) adds an extra layer of security by requiring two or more verification methods. Benefits:\n\n"
                "- Significantly reduces the risk of account compromise\n"
                "- Protects against password-based attacks\n"
                "- Can notify you of unauthorized access attempts\n"
                "- Is available on most major online services\n"
                "- Can use various factors: something you know (password), something you have (phone), or something you are (biometrics)",
                
                "Enabling two-factor authentication is one of the most effective security measures you can take. Best practices:\n\n"
                "- Use an authenticator app rather than SMS when possible\n"
                "- Keep backup codes in a secure location\n"
                "- Enable 2FA on all your important accounts\n"
                "- Consider using hardware security keys for maximum security\n"
                "- Be aware that 2FA can sometimes be bypassed through social engineering"
            ],
            
            "data breach": [
                "A data breach occurs when sensitive information is exposed due to unauthorized access. If your data is compromised:\n\n"
                "- Change your passwords immediately for affected accounts\n"
                "- Enable two-factor authentication where available\n"
                "- Monitor your accounts for suspicious activity\n"
                "- Check if your information was exposed using services like HaveIBeenPwned\n"
                "- Consider freezing your credit if financial information was exposed",
                
                "Data breaches are unfortunately common. To minimize impact:\n\n"
                "- Use different passwords for different services\n"
                "- Regularly check for news about breaches affecting services you use\n"
                "- Be cautious about what personal information you share online\n"
                "- Consider using a credit monitoring service\n"
                "- Stay alert for phishing attempts that may follow a breach"
            ],
            
            "encryption": [
                "Encryption converts data into a code to prevent unauthorized access. It's an essential privacy and security technology:\n\n"
                "- Use HTTPS websites whenever possible (look for the padlock icon)\n"
                "- Enable device encryption on your phones, tablets, and computers\n"
                "- Use encrypted messaging apps for sensitive communications\n"
                "- Consider encrypting important files and backups\n"
                "- Use a password manager that encrypts your stored passwords",
                
                "Encryption protects your data both when it's stored and when it's being transmitted. Important aspects:\n\n"
                "- End-to-end encryption means only the sender and recipient can read messages\n"
                "- Transport Layer Security (TLS) protects data in transit between your browser and websites\n"
                "- Full-disk encryption protects all data on your device if it's lost or stolen\n"
                "- Encrypted backups prevent unauthorized access to your backup data\n"
                "- Keep encryption keys and recovery phrases in secure, offline storage"
            ],
            
            "firewall": [
                "A firewall monitors and filters incoming and outgoing network traffic based on security rules. Benefits:\n\n"
                "- Blocks unauthorized access to your network and devices\n"
                "- Prevents malware from communicating with control servers\n"
                "- Alerts you to suspicious connection attempts\n"
                "- Can block access to malicious websites\n"
                "- Creates a barrier between your trusted internal network and untrusted external networks",
                
                "Both hardware and software firewalls are important security tools. Best practices:\n\n"
                "- Ensure your operating system's built-in firewall is enabled\n"
                "- Consider a hardware firewall for your home network\n"
                "- Configure firewall rules to block unnecessary incoming connections\n"
                "- Regularly check and update firewall settings\n"
                "- Use application-level firewalls for additional protection"
            ]
        }
        
        # General responses for questions that don't match specific topics
        self.general_responses = [
            "As your cybersecurity assistant, I can help with various security topics like phishing, password security, malware protection, and safe online practices. Could you provide more details about what you'd like to learn?",
            
            "I'm here to help with cybersecurity questions. Some popular topics include phishing awareness, creating strong passwords, protecting against malware, using VPNs, and implementing two-factor authentication. What specific area interests you?",
            
            "Cybersecurity encompasses many areas including threat detection, prevention, and security best practices. I'd be happy to discuss specific topics like social engineering, data breaches, encryption, or safe browsing habits. What would you like to know more about?",
            
            "I can provide information about cybersecurity threats and protection strategies. This includes recognizing phishing attempts, securing your devices, protecting your online accounts, and responding to potential security incidents. How can I assist you today?"
        ]
        
        # Greeting responses
        self.greetings = [
            "Hello! I'm CyberGuard, your AI cybersecurity assistant. How can I help you stay safe online today?",
            
            "Welcome to CyberGuard! I'm here to help with any cybersecurity questions or concerns you might have.",
            
            "Greetings! I'm your CyberGuard assistant, ready to help with cybersecurity information and advice. What can I assist you with?",
            
            "Hi there! I'm CyberGuard, your digital security companion. How can I help protect your digital life today?"
        ]
        
        # Farewell responses
        self.farewells = [
            "Thank you for using CyberGuard! Stay safe online, and feel free to return if you have more cybersecurity questions.",
            
            "Always happy to help with your cybersecurity needs. Remember to stay vigilant online!",
            
            "Stay secure, and don't hesitate to ask if you have more questions about cybersecurity!",
            
            "Remember, good cybersecurity is an ongoing practice. I'm here whenever you need more guidance or information."
        ]
    
    def get_response(self, query, conversation_history=None):
        """
        Generate a response based on the user's query
        
        Args:
            query: The user's question
            conversation_history: Previous messages in the conversation (optional)
            
        Returns:
            A response string
        """
        query = query.lower()
        
        # Check for greetings
        if self._is_greeting(query):
            return random.choice(self.greetings)
        
        # Check for farewells
        if self._is_farewell(query):
            return random.choice(self.farewells)
        
        # Check if query matches any known topics
        for topic, responses in self.topics.items():
            if topic in query or any(keyword in query for keyword in topic.split()):
                return random.choice(responses)
        
        # If we reach here, provide a general response
        return random.choice(self.general_responses)
    
    def _is_greeting(self, query):
        """Check if the query is a greeting"""
        greeting_patterns = [
            r"\bhello\b", r"\bhi\b", r"\bhey\b", r"\bgreetings\b", 
            r"\bgood morning\b", r"\bgood afternoon\b", r"\bgood evening\b",
            r"\bhowdy\b", r"\bwhat's up\b", r"\byo\b"
        ]
        
        return any(re.search(pattern, query) for pattern in greeting_patterns)
    
    def _is_farewell(self, query):
        """Check if the query is a farewell"""
        farewell_patterns = [
            r"\bbye\b", r"\bgoodbye\b", r"\bsee you\b", r"\bfarewell\b",
            r"\btake care\b", r"\bsee ya\b", r"\bciao\b", r"\bso long\b",
            r"\bthanks for your help\b", r"\bthank you\b", r"\bended\b"
        ]
        
        return any(re.search(pattern, query) for pattern in farewell_patterns)
    
    def stream_response(self, query, conversation_history=None, response_placeholder=None):
        """
        Stream a response word by word
        
        Args:
            query: The user's question
            conversation_history: Previous messages in the conversation (optional)
            response_placeholder: Streamlit placeholder to update with streaming text
            
        Returns:
            The complete response as a string
        """
        full_response = self.get_response(query, conversation_history)
        
        if response_placeholder:
            # Split the response into words for realistic streaming
            words = full_response.split()
            streamed_response = ""
            
            for i, word in enumerate(words):
                streamed_response += word + " "
                # Add punctuation without a space after it
                if i+1 < len(words) and words[i+1] in ['.', ',', '!', '?', ':', ';']:
                    streamed_response += words[i+1]
                    words[i+1] = ""
                
                response_placeholder.markdown(streamed_response + "▌")
                # Add a small delay for realistic typing effect
                import time
                time.sleep(0.05)
            
            # Display the final response
            response_placeholder.markdown(full_response)
        
        return full_response