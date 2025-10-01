# In reports.py
import os
from datetime import datetime, timezone, timedelta
from flask import current_app
from ai_integration import get_ai_advice, predict_threats, get_comprehensive_ai_analysis
import re

# Import pytz with fallback
try:
    import pytz
    PYTZ_AVAILABLE = True
except ImportError:
    PYTZ_AVAILABLE = False
    pytz = None

# Import FPDF with better error handling
try:
    from fpdf import FPDF
    FPDF_AVAILABLE = True
except ImportError as e:
    current_app.logger.error(f"FPDF import failed: {e}")
    FPDF_AVAILABLE = False
    FPDF = None

def clean_text_for_pdf(text):
    """Clean text to remove characters that cause FPDF encoding issues."""
    if not text:
        return ""
    
    # Replace Unicode emojis and symbols with ASCII equivalents
    emoji_replacements = {
        '✅': '[OK]',
        '❌': '[ERROR]',
        '⚠️': '[WARNING]',
        '🔍': '[SCAN]',
        '📊': '[DATA]',
        '🛡️': '[SHIELD]',
        '🔥': '[FIREWALL]',
        '🌐': '[NETWORK]',
        '📡': '[TRAFFIC]',
        '🤖': '[AI]',
        '📁': '[FOLDER]',
        '📄': '[DOCUMENT]',
        '🔒': '[SECURE]',
        '⏱️': '[TIME]',
        '💻': '[SYSTEM]',
        '🎯': '[TARGET]',
        '🔧': '[TOOL]',
        '📋': '[LIST]',
        '⭐': '[STAR]',
        '🚨': '[ALERT]',
        '💡': '[INFO]',
        '🔄': '[REFRESH]',
        '📈': '[CHART]',
        '🏠': '[HOME]',
        '🔑': '[KEY]',
        '📝': '[NOTE]',
        '⚡': '[FAST]',
        '🎨': '[DESIGN]',
        '🌟': '[FEATURE]',
        '🔐': '[LOCKED]',
        '📦': '[PACKAGE]',
        '🖥️': '[DESKTOP]',
        '📂': '[FOLDER]'
    }
    
    # Replace emojis first
    for emoji, replacement in emoji_replacements.items():
        text = text.replace(emoji, replacement)
    
    # Replace other problematic Unicode characters with ASCII equivalents
    text = text.replace('', '')  # Remove replacement character entirely
    text = text.replace('"', '"').replace('"', '"')  # Replace smart quotes
    text = text.replace(''', "'").replace(''', "'")  # Replace smart apostrophes
    text = text.replace('–', '-').replace('—', '-')  # Replace em/en dashes
    text = text.replace('…', '...')  # Replace ellipsis
    
    # Break long words (e.g., URLs/paths >80 chars)
    def break_long_words(t, max_len=80):
        words = t.split()
        broken = []
        for word in words:
            if len(word) > max_len:
                broken.append(' '.join([word[i:i+max_len] for i in range(0, len(word), max_len)]))  # Space-break
            else:
                broken.append(word)
        return ' '.join(broken)
    
    text = break_long_words(text)
    
    # Stricter: ASCII-only, remove non-printables/control chars
    text = ''.join(c for c in text if 32 <= ord(c) <= 126 or c in '\n\t')  # Printable ASCII + newline/tab
    
    # Handle encoding for latin-1 (FPDF compatibility)
    try:
        text.encode('latin-1')
    except UnicodeEncodeError:
        # Replace remaining problematic characters
        cleaned_chars = []
        for char in text:
            try:
                char.encode('latin-1')
                cleaned_chars.append(char)
            except UnicodeEncodeError:
                cleaned_chars.append('?')
        text = ''.join(cleaned_chars)
    
    # Clean up multiple spaces and newlines
    import re
    text = re.sub(r'\s+', ' ', text)
    text = text.strip()
    
    return text

def generate_pdf_report(data):
    current_app.logger.info("Starting PDF report generation...")
    current_app.logger.info(f"Report data keys: {list(data.keys()) if data else 'No data'}")
    
    # DEBUG: Check FPDF availability
    if not FPDF_AVAILABLE or FPDF is None:
        current_app.logger.error("FPDF not available, falling back to text report")
        return generate_text_report(data)
    
    # DEBUG: Check reports directory permissions
    reports_dir = os.path.join(current_app.root_path, 'static', 'reports')
    current_app.logger.info(f"Reports directory path: {reports_dir}")
    current_app.logger.info(f"Reports directory exists: {os.path.exists(reports_dir)}")
    if os.path.exists(reports_dir):
        current_app.logger.info(f"Reports directory writable: {os.access(reports_dir, os.W_OK)}")
    
    try:
        # Create PDF instance
        pdf = FPDF()
        pdf.set_left_margin(10)
        pdf.set_right_margin(10)
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        current_app.logger.info("PDF instance created successfully")
        
        # Add title
        pdf.set_font("Arial", 'B', 16)
        pdf.cell(200, 10, txt="A-Ryan Security Report", ln=1, align='C')
        pdf.ln(10)
        
        # Add date
        # Get local time for display
        if PYTZ_AVAILABLE and pytz:
            local_tz = pytz.timezone('America/Halifax')
            local_time = datetime.now(local_tz)
        else:
            # Fallback to system local time
            local_time = datetime.now()
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, txt=f"Generated on: {local_time.strftime('%Y-%m-%d %H:%M:%S %Z')}", ln=1)
        pdf.ln(10)
        current_app.logger.info("PDF header and date added")
        
        # Add Executive Summary with consistent AI Analysis
        pdf.set_font("Arial", 'B', 14)
        pdf.cell(200, 10, txt="Executive Summary", ln=1)
        pdf.set_font("Arial", size=12)
        
        current_app.logger.info("Getting comprehensive AI analysis for report...")
        try:
            # Get comprehensive AI analysis once and reuse it
            comprehensive_ai_analysis = get_comprehensive_ai_analysis(data)
            current_app.logger.info(f"Comprehensive AI analysis received: {len(comprehensive_ai_analysis.get('full_analysis', '')) if comprehensive_ai_analysis else 0} characters")
            
            if comprehensive_ai_analysis and comprehensive_ai_analysis.get('executive_summary'):
                executive_summary = comprehensive_ai_analysis['executive_summary']
                if len(executive_summary) > 500:
                    executive_summary = executive_summary[:500] + "..."
                
                # Clean text for FPDF compatibility
                clean_summary = clean_text_for_pdf(executive_summary)
                pdf.multi_cell(190, 10, txt=clean_summary)
                current_app.logger.info("AI executive summary added to report")
            else:
                # Use consistent risk assessment
                risk_level = assess_risk_level(data)
                fallback_summary = f"Security scan completed. Overall risk level: {risk_level}. Detailed findings below."
                pdf.multi_cell(190, 10, txt=fallback_summary)
                current_app.logger.warning("Using fallback executive summary with consistent risk assessment")
        except Exception as e:
            current_app.logger.error(f"Error getting AI analysis for executive section: {type(e).__name__}: {str(e)}")
            risk_level = assess_risk_level(data)
            fallback_summary = f"Security scan completed. Overall risk level: {risk_level}. Detailed findings below."
            pdf.multi_cell(190, 10, txt=fallback_summary)
        
        pdf.ln(10)
        
        # Add content based on data
        sections = [
            ('Antivirus Status', 'av'),
            ('Firewall Status', 'fw'),
            ('Network Status', 'net'),
            ('Process Security', 'processes')
        ]
        
        for title, key in sections:
            if key in data:
                pdf.set_font("Arial", 'B', 14)
                pdf.cell(190, 10, txt=title, ln=1)
                pdf.set_font("Arial", size=12)
                
                # Convert data to string and handle different formats
                content = str(data[key])
                if len(content) > 1000:
                    content = content[:1000] + "... [truncated]"
                
                # Clean content for PDF compatibility
                clean_content = clean_text_for_pdf(content)
                pdf.multi_cell(190, 10, txt=clean_content)
                pdf.ln(5)
        
        # Add comprehensive vulnerabilities section
        pdf.add_page()  # New page for vulnerability details
        pdf.set_font("Arial", 'B', 16)
        pdf.cell(200, 10, txt="Vulnerability Scan Results", ln=1, align='C')
        pdf.ln(10)
        
        # Add vulnerability summary
        if 'vulns' in data and data['vulns']:
            pdf.set_font("Arial", 'B', 14)
            pdf.cell(200, 10, txt="Vulnerability Summary", ln=1)
            pdf.set_font("Arial", size=12)
            
            total_vulns = sum(data['vulns'].values()) if isinstance(data['vulns'], dict) else 0
            pdf.multi_cell(190, 10, txt=f"Total Vulnerabilities Found: {total_vulns}")
            pdf.ln(5)
            
            pdf.set_font("Arial", 'B', 12)
            pdf.cell(200, 10, txt="Vulnerabilities by Package:", ln=1)
            pdf.set_font("Arial", size=11)
            
            for app, count in data['vulns'].items():
                severity_text = "HIGH PRIORITY" if count > 5 else "MEDIUM PRIORITY" if count > 2 else "LOW PRIORITY"
                vuln_line = clean_text_for_pdf(f"• {app}: {count} vulnerabilities ({severity_text})")
                pdf.cell(190, 8, txt=vuln_line, ln=1)
            pdf.ln(5)
        else:
            pdf.set_font("Arial", size=12)
            clean_text = clean_text_for_pdf("✅ No vulnerabilities detected in the scanned directories.")
            pdf.multi_cell(190, 10, txt=clean_text)
            pdf.ln(5)
        
        # Add OSV scan details if available
        if 'osv' in data and data['osv']:
            pdf.set_font("Arial", 'B', 14)
            pdf.cell(200, 10, txt="OSV Scanner Details", ln=1)
            pdf.set_font("Arial", size=11)
            
            osv_data = data['osv']
            if isinstance(osv_data, dict):
                if osv_data.get('raw_output'):
                    # Extract key information from raw output
                    raw_output = osv_data['raw_output']
                    lines = raw_output.split('\n')
                    
                    # Look for summary line
                    for line in lines:
                        if 'packages affected by' in line and 'vulnerabilities' in line:
                            clean_line = clean_text_for_pdf(line.strip())
                            summary_text = clean_text_for_pdf(f"📊 {clean_line}")
                            pdf.multi_cell(190, 8, txt=summary_text)
                            break
                    
                    # Look for severity breakdown
                    for line in lines:
                        if 'Critical' in line and 'High' in line and 'Medium' in line:
                            clean_line = clean_text_for_pdf(line.strip())
                            severity_text = clean_text_for_pdf(f"🔍 Severity Breakdown: {clean_line}")
                            pdf.multi_cell(190, 8, txt=severity_text)
                            break
                    
                elif osv_data.get('results'):
                    results_text = clean_text_for_pdf(f"OSV Results: {osv_data['results']}")
                    pdf.multi_cell(190, 8, txt=results_text)
                elif osv_data.get('error'):
                    error_text = clean_text_for_pdf(f"⚠️ OSV Scan Error: {osv_data['error']}")
                    pdf.multi_cell(190, 8, txt=error_text)
            pdf.ln(5)
        
        # Add Traffic Analysis section
        if 'traffic' in data and data['traffic']:
            pdf.set_font("Arial", 'B', 14)
            pdf.cell(200, 10, txt="Network Traffic Analysis", ln=1)
            pdf.set_font("Arial", size=12)
            
            traffic_summary = f"Analyzed {len(data['traffic'])} network connections"
            clean_traffic = clean_text_for_pdf(traffic_summary)
            pdf.multi_cell(190, 10, txt=clean_traffic)
            pdf.ln(5)
        
        # Add Process Security Analysis section
        if 'processes' in data and data['processes'] and not data['processes'].get('error'):
            pdf.set_font("Arial", 'B', 14)
            pdf.cell(200, 10, txt="Process Security Analysis", ln=1)
            pdf.set_font("Arial", size=12)
            
            processes_data = data['processes']
            process_summary = f"Scanned {processes_data.get('total_processes', 0)} processes"
            
            if processes_data.get('suspicious_processes', 0) > 0:
                process_summary += f", found {processes_data['suspicious_processes']} suspicious processes"
            
            if processes_data.get('security_analysis'):
                risk_level = processes_data['security_analysis'].get('risk_level', 'UNKNOWN')
                process_summary += f". Process security risk level: {risk_level}"
            
            clean_process_summary = clean_text_for_pdf(process_summary)
            pdf.multi_cell(190, 10, txt=clean_process_summary)
            
            # Add key findings if available
            if processes_data.get('security_analysis', {}).get('findings'):
                pdf.ln(3)
                pdf.set_font("Arial", 'B', 12)
                pdf.cell(200, 8, txt="Key Process Findings:", ln=1)
                pdf.set_font("Arial", size=11)
                
                for finding in processes_data['security_analysis']['findings'][:3]:
                    clean_finding = clean_text_for_pdf(f"• {finding}")
                    pdf.multi_cell(190, 6, txt=clean_finding)
            
            pdf.ln(5)
        
        # Add comprehensive AI recommendations section
        pdf.add_page()  # New page for AI recommendations
        pdf.set_font("Arial", 'B', 16)
        pdf.cell(200, 10, txt="AI Security Recommendations", ln=1, align='C')
        pdf.ln(10)
        
        current_app.logger.info("Using comprehensive AI analysis for recommendations...")
        try:
            # Reuse the comprehensive analysis from earlier
            if 'comprehensive_ai_analysis' in locals() and comprehensive_ai_analysis:
                recommendations = comprehensive_ai_analysis.get('recommendations', '')
                if recommendations:
                    pdf.set_font("Arial", 'B', 14)
                    pdf.cell(200, 10, txt="Detailed Analysis & Recommendations", ln=1)
                    pdf.set_font("Arial", size=11)
                    
                    # Clean and format AI recommendations
                    if len(recommendations) > 3000:
                        recommendations = recommendations[:3000] + "\n\n[Analysis truncated for report length]"
                    
                    # Clean text for FPDF compatibility
                    clean_recommendations = clean_text_for_pdf(recommendations)
                    pdf.multi_cell(190, 8, txt=clean_recommendations)
                    pdf.ln(10)
                    current_app.logger.info("Consistent AI recommendations added to PDF")
                else:
                    pdf.set_font("Arial", size=12)
                    pdf.multi_cell(190, 10, txt="AI recommendations are currently unavailable. Please ensure the AI service is running.")
                    current_app.logger.warning("No recommendations in comprehensive analysis")
            else:
                # Fallback to single AI call if comprehensive analysis failed
                current_app.logger.warning("Comprehensive analysis not available, falling back to single AI call")
                ai_advice = get_ai_advice(data)
                if ai_advice:
                    pdf.set_font("Arial", size=11)
                    clean_advice = clean_text_for_pdf(ai_advice[:3000])
                    pdf.multi_cell(190, 8, txt=clean_advice)
                else:
                    pdf.set_font("Arial", size=12)
                    pdf.multi_cell(190, 10, txt="AI recommendations could not be generated at this time.")
        except Exception as e:
            current_app.logger.error(f"Error adding AI recommendations to PDF: {type(e).__name__}: {str(e)}")
            pdf.set_font("Arial", size=12)
            pdf.multi_cell(190, 10, txt="AI recommendations could not be generated at this time.")
        
        # Add Risk Assessment section
        pdf.ln(10)
        pdf.set_font("Arial", 'B', 14)
        pdf.cell(200, 10, txt="Risk Assessment", ln=1)
        pdf.set_font("Arial", size=12)
        
        risk_level = assess_risk_level(data)
        risk_text = clean_text_for_pdf(f"Overall Risk Level: {risk_level}")
        pdf.multi_cell(190, 10, txt=risk_text)
        
        # Create reports directory if it doesn't exist
        reports_dir = os.path.join(current_app.root_path, 'static', 'reports')
        os.makedirs(reports_dir, exist_ok=True)
        current_app.logger.info(f"Reports directory ensured: {reports_dir}")
        
        # Generate filename with local time
        if PYTZ_AVAILABLE and pytz:
            local_tz = pytz.timezone('America/Halifax')
            local_time = datetime.now(local_tz)
        else:
            # Fallback to system local time
            local_time = datetime.now()
        timestamp = local_time.strftime("%Y%m%d_%H%M%S")
        filename = f"security_report_{timestamp}.pdf"
        filepath = os.path.join(reports_dir, filename)
        current_app.logger.info(f"Generated report filename: {filename}")
        
        # Save PDF
        current_app.logger.info(f"Attempting to save PDF to: {filepath}")
        try:
            pdf.output(filepath)
            current_app.logger.info(f"PDF report saved successfully to: {filepath}")
            
            # DEBUG: Verify file was actually created
            if os.path.exists(filepath):
                file_size = os.path.getsize(filepath)
                current_app.logger.info(f"PDF file created successfully, size: {file_size} bytes")
            else:
                current_app.logger.error("PDF file was not created despite no exception")
                return None
            
        except PermissionError as pe:
            current_app.logger.error(f"Permission error saving PDF: {pe}")
            return None
        except Exception as save_error:
            current_app.logger.error(f"Error saving PDF file: {type(save_error).__name__}: {save_error}")
            return None
        
        return f"/static/reports/{filename}"
        
    except Exception as e:
        current_app.logger.error(f"Critical error generating PDF report: {type(e).__name__}: {str(e)}")
        current_app.logger.error(f"Error occurred at line: {e.__traceback__.tb_lineno if e.__traceback__ else 'unknown'}")
        current_app.logger.error(f"Falling back to text report generation...")
        # Fallback to a simple text file
        fallback_result = generate_text_report(data)
        current_app.logger.info(f"Fallback text report result: {fallback_result}")
        return fallback_result

def assess_risk_level(data):
    """Assess overall risk level based on security data"""
    risk_score = 0
    
    # Check for errors in security components - handle both dict and string data
    av_data = data.get('av', {})
    if isinstance(av_data, dict) and av_data.get('error'):
        risk_score += 3
    elif isinstance(av_data, str) and 'error' in av_data.lower():
        risk_score += 3
    
    fw_data = data.get('fw', {})
    if isinstance(fw_data, dict) and fw_data.get('error'):
        risk_score += 3
    elif isinstance(fw_data, str) and 'error' in fw_data.lower():
        risk_score += 3
    
    net_data = data.get('net', {})
    if isinstance(net_data, dict) and net_data.get('error'):
        risk_score += 2
    elif isinstance(net_data, str) and 'error' in net_data.lower():
        risk_score += 2
    
    # Check for vulnerabilities
    vulns_data = data.get('vulns')
    if vulns_data:
        if isinstance(vulns_data, dict):
            vuln_count = sum(vulns_data.values())
        else:
            # If it's a string, try to extract numbers or assume some vulnerabilities exist
            vuln_count = 1
            
        if vuln_count > 10:
            risk_score += 3
        elif vuln_count > 5:
            risk_score += 2
        elif vuln_count > 0:
            risk_score += 1
    
    # Determine risk level
    if risk_score >= 6:
        return "HIGH - Immediate attention required"
    elif risk_score >= 3:
        return "MEDIUM - Review and address issues"
    else:
        return "LOW - System appears secure"

def generate_text_report(data):
    try:
        # Create reports directory if it doesn't exist
        reports_dir = os.path.join(current_app.root_path, 'static', 'reports')
        os.makedirs(reports_dir, exist_ok=True)
        
        # Generate filename with local time
        if PYTZ_AVAILABLE and pytz:
            local_tz = pytz.timezone('America/Halifax')
            local_time = datetime.now(local_tz)
        else:
            # Fallback to system local time
            local_time = datetime.now()
        timestamp = local_time.strftime("%Y%m%d_%H%M%S")
        filename = f"security_report_{timestamp}.txt"
        filepath = os.path.join(reports_dir, filename)
        
        # Create text content
        # Get local time for display
        if PYTZ_AVAILABLE and pytz:
            local_tz = pytz.timezone('America/Halifax')
            local_time = datetime.now(local_tz)
        else:
            # Fallback to system local time
            local_time = datetime.now()
        content = f"A-Ryan Security Report\n"
        content += f"Generated on: {local_time.strftime('%Y-%m-%d %H:%M:%S %Z')}\n"
        content += "=" * 50 + "\n\n"
        
        # Add Executive Summary with consistent analysis
        content += "EXECUTIVE SUMMARY\n"
        content += "-" * 20 + "\n"
        current_app.logger.info("Getting comprehensive AI analysis for text report...")
        try:
            # Get comprehensive AI analysis once
            comprehensive_ai_analysis = get_comprehensive_ai_analysis(data)
            if comprehensive_ai_analysis and comprehensive_ai_analysis.get('executive_summary'):
                content += comprehensive_ai_analysis['executive_summary'] + "\n\n"
                current_app.logger.info("Consistent AI summary added to text report")
            else:
                risk_level = assess_risk_level(data)
                content += f"Security scan completed. Overall risk level: {risk_level}. Detailed findings below.\n\n"
                current_app.logger.warning("Using fallback summary with consistent risk assessment")
        except Exception as e:
            current_app.logger.error(f"Error getting AI analysis for text report: {type(e).__name__}: {str(e)}")
            risk_level = assess_risk_level(data)
            content += f"Security scan completed. Overall risk level: {risk_level}. AI analysis unavailable.\n\n"
        
        # Add Risk Assessment
        risk_level = assess_risk_level(data)
        content += f"OVERALL RISK LEVEL: {risk_level}\n\n"
        
        sections = [
            ('Antivirus Status', 'av'),
            ('Firewall Status', 'fw'),
            ('Network Status', 'net'),
            ('Process Security', 'processes')
        ]
        
        for title, key in sections:
            if key in data:
                content += f"{title.upper()}:\n"
                content += "-" * len(title) + "\n"
                content += str(data[key]) + "\n\n"
                
        # Enhanced vulnerability section for text report
        content += "VULNERABILITY SCAN RESULTS\n"
        content += "=" * 25 + "\n"
        
        if 'vulns' in data and data['vulns']:
            total_vulns = sum(data['vulns'].values()) if isinstance(data['vulns'], dict) else 0
            content += f"Total Vulnerabilities Found: {total_vulns}\n\n"
            
            content += "Vulnerabilities by Package:\n"
            content += "-" * 25 + "\n"
            for app, count in data['vulns'].items():
                severity = "HIGH PRIORITY" if count > 5 else "MEDIUM PRIORITY" if count > 2 else "LOW PRIORITY"
                content += f"• {app}: {count} vulnerabilities ({severity})\n"
            content += "\n"
        else:
            content += "✅ No vulnerabilities detected in the scanned directories.\n\n"
        
        # Add OSV scan details
        if 'osv' in data and data['osv']:
            content += "OSV Scanner Details:\n"
            content += "-" * 20 + "\n"
            
            osv_data = data['osv']
            if isinstance(osv_data, dict):
                if osv_data.get('raw_output'):
                    raw_output = osv_data['raw_output']
                    lines = raw_output.split('\n')
                    
                    # Extract key information
                    for line in lines:
                        if 'packages affected by' in line and 'vulnerabilities' in line:
                            content += f"📊 {line.strip()}\n"
                            break
                    
                    for line in lines:
                        if 'Critical' in line and 'High' in line and 'Medium' in line:
                            content += f"🔍 Severity Breakdown: {line.strip()}\n"
                            break
                            
                elif osv_data.get('results'):
                    content += f"OSV Results: {osv_data['results']}\n"
                elif osv_data.get('error'):
                    content += f"⚠️ OSV Scan Error: {osv_data['error']}\n"
            content += "\n"
        
        if 'traffic' in data and data['traffic']:
            content += "NETWORK TRAFFIC:\n"
            content += "-" * 15 + "\n"
            content += f"Analyzed {len(data['traffic'])} network connections\n\n"
        
        # Add Process Security section
        if 'processes' in data and data['processes'] and not data['processes'].get('error'):
            content += "PROCESS SECURITY ANALYSIS\n"
            content += "=" * 25 + "\n"
            
            processes_data = data['processes']
            content += f"Total processes scanned: {processes_data.get('total_processes', 0)}\n"
            content += f"Suspicious processes detected: {processes_data.get('suspicious_processes', 0)}\n"
            content += f"High resource usage processes: {processes_data.get('high_resource_processes', 0)}\n"
            content += f"Network active processes: {processes_data.get('network_processes', 0)}\n\n"
            
            # Add security analysis
            if processes_data.get('security_analysis'):
                analysis = processes_data['security_analysis']
                content += f"Process Security Risk Level: {analysis.get('risk_level', 'UNKNOWN')}\n\n"
                
                if analysis.get('findings'):
                    content += "Key Findings:\n"
                    for finding in analysis['findings'][:5]:
                        content += f"• {finding}\n"
                    content += "\n"
                
                if analysis.get('recommendations'):
                    content += "Process Security Recommendations:\n"
                    for rec in analysis['recommendations'][:5]:
                        content += f"• {rec}\n"
                    content += "\n"
            
            # Add suspicious process details
            if processes_data.get('suspicious_details'):
                content += "Suspicious Process Details:\n"
                content += "-" * 25 + "\n"
                for proc in processes_data['suspicious_details'][:3]:
                    content += f"• {proc.get('name', 'Unknown')} (PID: {proc.get('pid', 'N/A')})\n"
                    content += f"  Path: {proc.get('exe_path', 'Unknown')}\n"
                    if proc.get('suspicious_indicators'):
                        content += f"  Indicators: {', '.join(proc['suspicious_indicators'][:2])}\n"
                    content += "\n"
        
        # Add AI Recommendations with consistent analysis
        content += "AI SECURITY RECOMMENDATIONS\n"
        content += "=" * 30 + "\n"
        current_app.logger.info("Using comprehensive AI analysis for text report recommendations...")
        try:
            # Reuse comprehensive analysis if available
            if 'comprehensive_ai_analysis' in locals() and comprehensive_ai_analysis:
                recommendations = comprehensive_ai_analysis.get('recommendations', '')
                if recommendations:
                    content += recommendations + "\n\n"
                    current_app.logger.info("Consistent AI recommendations added to text report")
                else:
                    content += "AI recommendations are currently unavailable.\n\n"
                    current_app.logger.warning("No recommendations in comprehensive analysis")
            else:
                # Fallback to single AI call
                ai_advice = get_ai_advice(data)
                if ai_advice:
                    content += ai_advice + "\n\n"
                    current_app.logger.info("Fallback AI recommendations added to text report")
                else:
                    content += "AI recommendations are currently unavailable.\n\n"
        except Exception as e:
            current_app.logger.error(f"Error getting AI recommendations for text report: {type(e).__name__}: {str(e)}")
            content += "Could not generate AI recommendations.\n\n"
        
        content += "End of Report\n"
        content += "=" * 50 + "\n"
        
        # Save text file
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        
        return f"/static/reports/{filename}"
        
    except Exception as e:
        current_app.logger.error(f"Error generating text report: {e}")
        return None