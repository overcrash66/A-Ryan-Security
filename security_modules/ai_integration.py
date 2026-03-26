import ollama
import logging
import os
import json
import requests

def get_ai_client(user_id=None):
    """
    Get configured AI client based on user settings or system defaults.
    
    Args:
        user_id: Optional user ID to get user-specific config
        
    Returns:
        Tuple of (client_type, config_dict)
        - client_type: 'ollama' or 'openai'
        - config_dict: contains api_url, model, api_key, etc.
    """
    from security_modules import ai_config
    
    # Get user config or defaults
    config = ai_config.get_ai_config(user_id)
    
    api_url = config.get('api_url', 'http://127.0.0.1:11434')
    model = config.get('default_model', 'qwen2.5-coder:3b')
    provider = config.get('provider', 'ollama')
    
    # Get decrypted API key if available
    api_key = None
    if user_id and config.get('api_key'):
        api_key = ai_config.get_decrypted_api_key(user_id)
    
    return provider, {
        'api_url': api_url,
        'model': model,
        'api_key': api_key,
        'provider': provider
    }


def call_ai_api(prompt, config):
    """
    Call AI API based on provider type.
    
    Args:
        prompt: The prompt to send to the AI
        config: Configuration dict with api_url, model, api_key, provider
        
    Returns:
        AI response content or None on failure
    """
    provider = config.get('provider', 'ollama')
    
    if provider == 'ollama':
        return call_ollama(prompt, config)
    elif provider == 'openai':
        return call_openai_compatible(prompt, config)
    else:
        logging.error(f"Unsupported provider: {provider}")
        return None


def call_ollama(prompt, config):
    """
    Call Ollama API.
    
    Args:
        prompt: The prompt to send
        config: Configuration dict
        
    Returns:
        AI response or None on failure
    """
    api_url = config.get('api_url', 'http://127.0.0.1:11434')
    model = config.get('model', 'qwen2.5-coder:3b')
    
    try:
        client = ollama.Client(host=api_url)
        response = client.chat(model=model, messages=[{'role': 'user', 'content': prompt}])
        return response['message']['content']
    except Exception as e:
        logging.error(f"Ollama API call failed: {e}")
        return None


def call_openai_compatible(prompt, config):
    """
    Call OpenAI-compatible API.
    
    Args:
        prompt: The prompt to send
        config: Configuration dict with api_url, model, api_key
        
    Returns:
        AI response or None on failure
    """
    api_url = config.get('api_url', '')
    model = config.get('model', '')
    api_key = config.get('api_key', '')
    
    if not api_url or not model:
        logging.error("OpenAI-compatible API requires api_url and model")
        return None
    
    # Ensure URL ends properly for API calls
    if not api_url.endswith('/'):
        api_url += '/'
    
    headers = {
        'Content-Type': 'application/json'
    }
    
    if api_key:
        headers['Authorization'] = f'Bearer {api_key}'
    
    payload = {
        'model': model,
        'messages': [{'role': 'user', 'content': prompt}],
        'temperature': 0.7
    }
    
    try:
        # Try /v1/chat/completions first (OpenAI standard)
        response = requests.post(
            f"{api_url}v1/chat/completions",
            headers=headers,
            json=payload,
            timeout=120
        )
        
        if response.status_code == 200:
            data = response.json()
            if 'choices' in data and len(data['choices']) > 0:
                return data['choices'][0]['message']['content']
        elif response.status_code == 401:
            logging.warning("OpenAI API key may be invalid")
        elif response.status_code == 404:
            # Try without /v1/ prefix
            response = requests.post(
                f"{api_url}chat/completions",
                headers=headers,
                json=payload,
                timeout=120
            )
            if response.status_code == 200:
                data = response.json()
                if 'choices' in data and len(data['choices']) > 0:
                    return data['choices'][0]['message']['content']
        else:
            logging.error(f"OpenAI-compatible API returned {response.status_code}: {response.text}")
            
    except requests.exceptions.Timeout:
        logging.error("OpenAI-compatible API request timed out")
    except requests.exceptions.ConnectionError as e:
        logging.error(f"OpenAI-compatible API connection failed: {e}")
    except Exception as e:
        logging.error(f"OpenAI-compatible API call failed: {e}")
    
    return None


def get_comprehensive_ai_analysis(results):
    """
    Get comprehensive AI analysis that provides consistent executive summary and recommendations.
    This prevents contradictory information by analyzing all data in a single AI call.
    """
    # Enhanced prompt for comprehensive analysis
    prompt = build_comprehensive_analysis_prompt(results)
    
    logging.info("Starting comprehensive AI analysis...")
    logging.info(f"Comprehensive prompt length: {len(prompt)} characters")
    
    try:
        # Get configured client and model
        provider, config = get_ai_client()
        
        logging.info(f"Using {provider} at {config['api_url']}, model: {config['model']}")
        
        # Use available model
        analysis = call_ai_api(prompt, config)
        
        if analysis:
            logging.info(f'Comprehensive AI analysis generated successfully. Length: {len(analysis)} characters')
            # Parse the structured response
            parsed_analysis = parse_ai_analysis(analysis)
            return parsed_analysis
        else:
            raise Exception("AI API call returned no response")
            
    except Exception as e:
        logging.error(f'Comprehensive AI analysis error: {type(e).__name__}: {str(e)}')
        
        # Try fallback to default Ollama port if primary fails
        try:
            from security_modules import ai_config
            fallback_url = f"http://127.0.0.1:{ai_config.FALLBACK_PORT}"
            fallback_config = config.copy()
            fallback_config['api_url'] = fallback_url
            
            logging.info(f"Trying fallback at {fallback_url}")
            analysis = call_ai_api(prompt, fallback_config)
            
            if analysis:
                parsed_analysis = parse_ai_analysis(analysis)
                return parsed_analysis
        except Exception as fallback_error:
            logging.error(f'Comprehensive AI analysis fallback failed: {type(fallback_error).__name__}: {str(fallback_error)}')
        
        return None

def parse_ai_analysis(analysis_text):
    """Parse AI analysis into structured components."""
    try:
        # Try to extract structured sections from the AI response
        sections = {
            'executive_summary': '',
            'risk_level': '',
            'recommendations': '',
            'full_analysis': analysis_text
        }
        
        lines = analysis_text.split('\n')
        current_section = None
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # Look for section headers
            if 'RISK ASSESSMENT' in line.upper() or 'OVERALL RISK' in line.upper():
                current_section = 'risk_level'
                continue
            elif 'EXECUTIVE' in line.upper() or 'SUMMARY' in line.upper():
                current_section = 'executive_summary'
                continue
            elif 'RECOMMENDATION' in line.upper() or 'ACTION' in line.upper():
                current_section = 'recommendations'
                continue
            
            # Add content to current section
            if current_section:
                if sections[current_section]:
                    sections[current_section] += ' ' + line
                else:
                    sections[current_section] = line
        
        # If no structured sections found, use the first part as executive summary
        if not sections['executive_summary'] and analysis_text:
            first_paragraph = analysis_text.split('\n\n')[0]
            sections['executive_summary'] = first_paragraph[:500]
        
        # Extract risk level from text if not found in dedicated section
        if not sections['risk_level']:
            risk_keywords = ['HIGH', 'MEDIUM', 'LOW', 'CRITICAL']
            for keyword in risk_keywords:
                if keyword in analysis_text.upper():
                    sections['risk_level'] = keyword
                    break
        
        logging.info(f"Parsed AI analysis: executive_summary={len(sections['executive_summary'])} chars, "
                    f"risk_level='{sections['risk_level']}', recommendations={len(sections['recommendations'])} chars")
        
        return sections
        
    except Exception as e:
        logging.error(f"Error parsing AI analysis: {e}")
        return {
            'executive_summary': analysis_text[:500] if analysis_text else '',
            'risk_level': '',
            'recommendations': analysis_text[500:] if len(analysis_text) > 500 else '',
            'full_analysis': analysis_text
        }

def build_comprehensive_analysis_prompt(results):
    """Build a comprehensive prompt that ensures consistent analysis."""
    
    prompt_parts = [
        "You are a cybersecurity expert tasked with delivering a comprehensive and consistent security analysis based on the provided scan data.",
        "IMPORTANT: Ensure your analysis is cohesive, non-contradictory, and presented as a single, unified assessment.",
        "Focus on identifying vulnerabilities, assessing their severity, and providing actionable recommendations for mitigation.",
        "Structure your response clearly, using sections such as Overview, Findings, and Recommendations, as appropriate.",
        "",
        "=== SECURITY SCAN DATA ===",
        f"Raw scan results: {results}",
        "",
        "=== INSTRUCTIONS ===",
        "1. Analyze the raw scan results thoroughly, interpreting technical details accurately.",
        "2. Avoid speculative assumptions; base your analysis solely on the provided data.",
        "3. Use clear, professional language suitable for both technical and non-technical stakeholders.",
        "4. If the scan results are incomplete or unclear, note this in your analysis and suggest next steps."
    ]
    
    # Extract and analyze key data points
    vulns_data = results.get('vulns', {})
    osv_data = results.get('osv', {})
    av_data = results.get('av', '')
    fw_data = results.get('fw', '')
    net_data = results.get('net', '')
    traffic_data = results.get('traffic', [])
    process_data = results.get('processes', {})
    
    # Vulnerability Analysis
    total_vulns = 0
    if vulns_data and isinstance(vulns_data, dict):
        total_vulns = sum(vulns_data.values())
    
    prompt_parts.extend([
        "=== KEY FINDINGS ===",
        f"• Total vulnerabilities detected: {total_vulns}",
        f"• Antivirus status: {'Active' if av_data and 'error' not in str(av_data).lower() else 'Issues detected'}",
        f"• Firewall status: {'Active' if fw_data and 'error' not in str(fw_data).lower() else 'Issues detected'}",
        f"• Network connections analyzed: {len(traffic_data) if traffic_data else 0}",
        ""
    ])
    
    # Add process security findings
    if process_data and not process_data.get('error'):
        prompt_parts.extend([
            "=== PROCESS SECURITY FINDINGS ===",
            f"• Total processes scanned: {process_data.get('total_processes', 0)}",
            f"• Suspicious processes detected: {process_data.get('suspicious_processes', 0)}",
            f"• High resource usage processes: {process_data.get('high_resource_processes', 0)}",
            f"• Network active processes: {process_data.get('network_processes', 0)}",
        ])
        
        # Add process security analysis if available
        if process_data.get('security_analysis'):
            analysis = process_data['security_analysis']
            prompt_parts.append(f"• Process security risk level: {analysis.get('risk_level', 'UNKNOWN')}")
            
            if analysis.get('findings'):
                prompt_parts.append("• Key process findings:")
                for finding in analysis['findings'][:3]:
                    prompt_parts.append(f"  - {finding}")
        
        prompt_parts.append("")
    
    # OSV specific findings
    if osv_data and osv_data.get('raw_output'):
        raw_output = osv_data['raw_output']
        if 'Critical' in raw_output:
            prompt_parts.append("• CRITICAL vulnerabilities detected in OSV scan")
        elif 'High' in raw_output:
            prompt_parts.append("• HIGH severity vulnerabilities detected in OSV scan")
        elif 'packages affected' in raw_output:
            # Extract summary
            lines = raw_output.split('\n')
            for line in lines:
                if 'packages affected by' in line and 'vulnerabilities' in line:
                    prompt_parts.append(f"• OSV Summary: {line.strip()}")
                    break
    
    prompt_parts.extend([
        "",
        "=== ANALYSIS REQUIREMENTS ===",
        "Provide your analysis in the following structure:",
        "",
        "EXECUTIVE SUMMARY:",
        "Provide a 2-3 sentence summary of the overall security posture.",
        "",
        "RISK ASSESSMENT:",
        "State the overall risk level (CRITICAL/HIGH/MEDIUM/LOW) with brief justification.",
        "",
        "RECOMMENDATIONS:",
        "List 3-5 specific, actionable recommendations based on the findings.",
        "Include process security recommendations if suspicious processes were detected.",
        "",
        "IMPORTANT: Ensure your risk assessment is consistent with your executive summary and recommendations.",
        "Consider process security findings when determining overall risk level."
    ])
    
    return "\n".join(prompt_parts)


def get_ai_advice(results):
    # Enhanced prompt generation based on available data
    prompt = build_enhanced_security_prompt(results)
    
    # Add diagnostic logging
    logging.info("Starting AI advice generation...")
    logging.info(f"Enhanced prompt length: {len(prompt)} characters")
    
    try:
        # Test connection first
        logging.info("Testing AI connection...")
        
        # Get configured client and model
        provider, config = get_ai_client()
        
        logging.info(f"Using {provider} at {config['api_url']}, model: {config['model']}")
        
        advice = call_ai_api(prompt, config)
        
        if advice:
            logging.info(f'AI advice generated successfully. Length: {len(advice)} characters')
            return advice
        else:
            raise Exception("AI API call returned no response")
            
    except Exception as e:
        logging.error(f'AI error details: {type(e).__name__}: {str(e)}')
        
        # Try fallback to default Ollama port if primary fails
        try:
            from security_modules import ai_config
            fallback_url = f"http://127.0.0.1:{ai_config.FALLBACK_PORT}"
            fallback_config = config.copy()
            fallback_config['api_url'] = fallback_url
            
            logging.info(f"Trying fallback at {fallback_url}")
            advice = call_ai_api(prompt, fallback_config)
            
            if advice:
                logging.info(f'AI advice generated on fallback. Length: {len(advice)} characters')
                return advice
        except Exception as fallback_error:
            logging.error(f'Fallback also failed: {type(fallback_error).__name__}: {str(fallback_error)}')
        
        return f"Failed to connect to AI service. Please check that your AI provider is running and accessible."

def build_enhanced_security_prompt(results):
    """Build an enhanced prompt that provides detailed context for AI analysis."""
    
    # Include raw results for backward compatibility with tests
    prompt_parts = [
        "You are a cybersecurity expert analyzing a comprehensive security scan. Provide detailed, actionable recommendations.",
        f"\n=== RAW SCAN DATA ===\n{results}",
        "\n=== SECURITY SCAN ANALYSIS ===\n"
    ]
    
    # Extract vulnerability data if available
    vulns_data = results.get('vulns', {})
    osv_data = results.get('osv', {})
    av_data = results.get('av', '')
    fw_data = results.get('fw', '')
    net_data = results.get('net', '')
    traffic_data = results.get('traffic', [])
    
    # Vulnerability Analysis Section
    if vulns_data or (osv_data and osv_data.get('raw_output')):
        prompt_parts.append("🔍 VULNERABILITY SCAN RESULTS:")
        
        if vulns_data:
            total_vulns = sum(vulns_data.values()) if isinstance(vulns_data, dict) else 0
            prompt_parts.append(f"- Total vulnerabilities found: {total_vulns}")
            
            if isinstance(vulns_data, dict):
                for package, count in vulns_data.items():
                    prompt_parts.append(f"- {package}: {count} vulnerabilities")
        
        if osv_data and osv_data.get('raw_output'):
            # Extract key information from raw output
            raw_output = osv_data['raw_output']
            if 'Critical' in raw_output or 'High' in raw_output:
                prompt_parts.append("- CRITICAL/HIGH severity vulnerabilities detected!")
            if 'packages affected' in raw_output:
                # Extract summary line
                lines = raw_output.split('\n')
                for line in lines:
                    if 'packages affected by' in line and 'vulnerabilities' in line:
                        prompt_parts.append(f"- Summary: {line.strip()}")
                        break
        
        prompt_parts.append("")
    else:
        prompt_parts.append("🔍 VULNERABILITY SCAN: No vulnerabilities detected or scan not performed.\n")
    
    # Other Security Components
    if av_data and av_data != "Antivirus scan unavailable":
        prompt_parts.append(f"🛡️ ANTIVIRUS STATUS: {av_data}")
    
    if fw_data and fw_data != "Firewall status unavailable":
        prompt_parts.append(f"🔥 FIREWALL STATUS: {fw_data}")
    
    if net_data and net_data != "Network scan unavailable":
        prompt_parts.append(f"🌐 NETWORK SECURITY: {net_data}")
    
    if traffic_data and len(traffic_data) > 0:
        prompt_parts.append(f"📡 NETWORK TRAFFIC: {len(traffic_data)} connections analyzed")
    
    # Analysis Request
    prompt_parts.extend([
        "\n=== ANALYSIS REQUEST ===",
        "Please provide:",
        "1. RISK ASSESSMENT: Overall security risk level (Critical/High/Medium/Low) with justification",
        "2. PRIORITY ACTIONS: Most urgent security issues to address immediately",
        "3. VULNERABILITY REMEDIATION: Specific steps to fix identified vulnerabilities",
        "4. SECURITY IMPROVEMENTS: Additional hardening recommendations",
        "5. MONITORING RECOMMENDATIONS: What to monitor going forward",
        "",
        "Focus especially on vulnerability findings if present. Be specific and actionable."
    ])
    
    return "\n".join(prompt_parts)

def predict_threats(logs):
    prompt = f"From logs: {logs}, predict potential future threats and mitigation strategies."
    
    logging.info("Starting threat prediction...")
    
    try:
        # Get configured client and model
        provider, config = get_ai_client()
        
        logging.info(f"Using {provider} at {config['api_url']}, model: {config['model']}")
        
        prediction = call_ai_api(prompt, config)
        
        if prediction:
            logging.info(f'Threat prediction generated successfully. Length: {len(prediction)} characters')
            return prediction
        else:
            raise Exception("AI API call returned no response")
            
    except Exception as e:
        logging.error(f'AI predict_threats error details: {type(e).__name__}: {str(e)}')
        
        try:
            # Try fallback to default Ollama port
            from security_modules import ai_config
            fallback_url = f"http://127.0.0.1:{ai_config.FALLBACK_PORT}"
            fallback_config = config.copy()
            fallback_config['api_url'] = fallback_url
            
            logging.info(f"Trying fallback at {fallback_url}")
            prediction = call_ai_api(prompt, fallback_config)
            
            if prediction:
                logging.info(f'Threat prediction generated on fallback. Length: {len(prediction)} characters')
                return prediction
        except Exception as fallback_error:
            logging.error(f'Threat prediction fallback failed: {type(fallback_error).__name__}: {str(fallback_error)}')
        
        return "AI prediction service temporarily unavailable due to connection issues."
