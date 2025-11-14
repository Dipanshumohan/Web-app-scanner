#!/usr/bin/env python3

from typing import Dict, List, Any, Optional
from datetime import datetime
import json
import os


class ReportGenerator:
    """
    PDF Report Generator for Security Scanner Results
    
    Features:
    - Professional PDF reports
    - Executive summary
    - Detailed vulnerability findings
    - Risk assessment
    - Remediation recommendations
    """
    
    def __init__(self):
        self.report_templates = {
            'sqli': 'SQL Injection',
            'xss': 'Cross-Site Scripting (XSS)',
            'crlf': 'CRLF Injection',
            'cmdi': 'Command Injection'
        }
    
    def generate_pdf_report_data(self, scan_results: List[Dict], scan_type: str = "",
                                target_url: str = "", crawled_urls: List[str] = None, 
                                scan_duration: float = 0) -> Dict[str, Any]:
        """
        Generate structured data for PDF report
        This data can be used by GUI applications to create PDF reports
        """
        
        vulnerable_results = [r for r in scan_results if r.get('is_vulnerable', False)]
        
        risk_distribution = {}
        for result in vulnerable_results:
            risk = result.get('risk_level', 'Unknown')
            risk_distribution[risk] = risk_distribution.get(risk, 0) + 1
        
        overall_risk = self._calculate_overall_risk(risk_distribution)
        
        crawled_urls = crawled_urls or []
        all_scanned_urls = list(set(r.get('url', '') for r in scan_results))
        
        report_data = {
            'report_info': {
                'title': f'{self.report_templates.get(scan_type, "Security")} Vulnerability Scan Report',
                'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'scanner_version': 'Web Security Scanner Beta v2.0',
                'target_url': target_url,
                'scan_type': scan_type.upper() if scan_type else 'Multiple',
                'crawling_enabled': len(crawled_urls) > 0,
                'total_crawled_urls': len(crawled_urls),
                'total_urls_scanned': len(all_scanned_urls),
                'vulnerable_urls': len(set(r.get('url', '') for r in vulnerable_results)),
                'total_vulnerabilities': len(vulnerable_results),
                'overall_risk': overall_risk,
                'scan_duration': f"{scan_duration:.2f} seconds" if scan_duration > 0 else 'N/A'
            },
            
            'scan_scope': {
                'primary_target': target_url,
                'crawled_urls': crawled_urls[:20],  # Limit to first 20 for display
                'total_crawled': len(crawled_urls),
                'scanned_urls': all_scanned_urls,
                'methodology': 'Automated crawling + vulnerability injection testing'
            },
            
            'executive_summary': {
                'risk_level': overall_risk,
                'key_findings': self._generate_key_findings(vulnerable_results, scan_type),
                'recommendations': self._generate_recommendations(scan_type, overall_risk),
                'risk_distribution': risk_distribution,
                'scan_coverage': f"{len(all_scanned_urls)} URLs tested from {len(crawled_urls) + 1} discovered URLs"
            },
            
            'detailed_results': self._format_detailed_results(vulnerable_results),
            
            'statistics': {
                'scan_duration': f"{scan_duration:.2f} seconds" if scan_duration > 0 else 'N/A',
                'total_requests': len(scan_results),
                'crawling_stats': {
                    'urls_discovered': len(crawled_urls),
                    'urls_with_parameters': len([url for url in crawled_urls if '?' in url and '=' in url]),
                    'urls_actually_scanned': len(all_scanned_urls)
                },
                'success_rate': f"{((len(scan_results) - len([r for r in scan_results if r.get('error_message')])) / len(scan_results) * 100):.1f}%" if scan_results else "0%",
                'vulnerability_density': f"{len(vulnerable_results) / len(all_scanned_urls) * 100:.1f}%" if all_scanned_urls else "0%",
                'vulnerability_types': self._get_vulnerability_types(vulnerable_results),
                'database_distribution': self._get_database_distribution(vulnerable_results) if scan_type == 'sqli' else {},
                'payload_distribution': self._get_payload_distribution(vulnerable_results),
                'confidence_scores': self._get_confidence_stats(vulnerable_results)
            },
            
            'remediation': self._generate_remediation_guide(scan_type),
            
            'appendix': {
                'methodology': self._get_methodology_description(scan_type),
                'references': self._get_references(scan_type),
                'technical_details': self._format_technical_details(scan_results)
            }
        }
        
        return report_data
    
    def _calculate_overall_risk(self, risk_distribution: Dict[str, int]) -> str:
        """Calculate overall risk level based on individual risks"""
        if risk_distribution.get('Critical', 0) > 0:
            return 'CRITICAL'
        elif risk_distribution.get('High', 0) > 0:
            return 'HIGH'
        elif risk_distribution.get('Medium', 0) > 0:
            return 'MEDIUM'
        elif risk_distribution.get('Low', 0) > 0:
            return 'LOW'
        else:
            return 'NO RISK'
    
    def _generate_key_findings(self, vulnerable_results: List[Dict], scan_type: str) -> List[str]:
        """Generate key findings for executive summary"""
        findings = []
        
        if not vulnerable_results:
            findings.append("No security vulnerabilities were identified during the scan.")
            return findings
        
        vulnerability_count = len(vulnerable_results)
        unique_urls = len(set(r.get('url', '') for r in vulnerable_results))
        
        if vulnerability_count == 1:
            findings.append(f"1 {self.report_templates.get(scan_type, 'security')} vulnerability was identified.")
        else:
            findings.append(f"{vulnerability_count} {self.report_templates.get(scan_type, 'security')} vulnerabilities were identified.")
        
        if unique_urls == 1:
            findings.append("Vulnerabilities were found in 1 unique URL.")
        else:
            findings.append(f"Vulnerabilities were found across {unique_urls} unique URLs.")
        
        if scan_type == 'sqli':
            databases = set(r.get('database_type') for r in vulnerable_results if r.get('database_type'))
            if databases:
                db_list = ', '.join(databases)
                findings.append(f"SQL injection vulnerabilities detected in {len(databases)} database types: {db_list}")
        
        elif scan_type == 'xss':
            xss_types = set(r.get('xss_type') for r in vulnerable_results if r.get('xss_type'))
            if xss_types:
                findings.append(f"XSS vulnerability types identified: {', '.join(xss_types)}")
        
        elif scan_type == 'crlf':
            injection_types = set(r.get('injection_type') for r in vulnerable_results if r.get('injection_type'))
            if injection_types:
                findings.append(f"CRLF injection types identified: {', '.join(injection_types)}")
        
        elif scan_type == 'cmdi':
            os_types = set(r.get('os_type') for r in vulnerable_results if r.get('os_type'))
            if os_types:
                findings.append(f"Command injection detected on operating systems: {', '.join(os_types)}")
        
        critical_count = len([r for r in vulnerable_results if r.get('risk_level') == 'Critical'])
        if critical_count > 0:
            findings.append(f"IMMEDIATE ACTION REQUIRED: {critical_count} critical vulnerabilities require urgent attention.")
        
        return findings
    
    def _generate_recommendations(self, scan_type: str, overall_risk: str) -> List[str]:
        """Generate recommendations based on scan type and risk level"""
        recommendations = []
        
        if overall_risk in ['CRITICAL', 'HIGH']:
            recommendations.append("IMMEDIATE ACTION REQUIRED: Fix identified vulnerabilities before deploying to production.")
        elif overall_risk == 'MEDIUM':
            recommendations.append("Address identified vulnerabilities in the next development cycle.")
        
        if scan_type == 'sqli':
            recommendations.extend([
                "Implement parameterized queries/prepared statements for all database interactions",
                "Use input validation and sanitization for all user inputs",
                "Apply the principle of least privilege to database accounts",
                "Consider using stored procedures with proper input validation",
                "Implement Web Application Firewall (WAF) as an additional layer of protection"
            ])
        
        elif scan_type == 'xss':
            recommendations.extend([
                "Implement proper output encoding for all user-generated content",
                "Use Content Security Policy (CSP) headers to prevent script execution",
                "Validate and sanitize all user inputs on both client and server side",
                "Use secure coding practices and XSS prevention libraries",
                "Regularly update and patch web application frameworks"
            ])
        
        elif scan_type == 'crlf':
            recommendations.extend([
                "Validate and sanitize all user inputs to remove CRLF characters",
                "Use secure HTTP header handling libraries",
                "Implement proper input encoding and output filtering",
                "Review and secure all redirect and header manipulation functionality",
                "Consider implementing strict header validation"
            ])
        
        elif scan_type == 'cmdi':
            recommendations.extend([
                "Avoid using system commands with user input whenever possible",
                "If system commands are necessary, use secure APIs and avoid shell execution",
                "Implement strict input validation and use allowlists for permitted values",
                "Use parameterized command execution or escape shell metacharacters",
                "Apply the principle of least privilege to application processes",
                "Consider using containerization to limit command execution scope"
            ])
        
        recommendations.extend([
            "Conduct regular security testing and code reviews",
            "Implement security monitoring and logging",
            "Keep all software components and dependencies up to date",
            "Provide security training for development team members"
        ])
        
        return recommendations
    
    def _format_detailed_results(self, vulnerable_results: List[Dict]) -> List[Dict]:
        """Format detailed vulnerability results"""
        detailed_results = []
        
        for i, result in enumerate(vulnerable_results, 1):
            detailed_result = {
                'id': i,
                'url': result.get('url', 'N/A'),
                'vulnerability_type': result.get('vulnerability_type', 'Unknown'),
                'risk_level': result.get('risk_level', 'Unknown'),
                'payload': result.get('payload', 'N/A'),
                'timestamp': result.get('timestamp', datetime.now()).strftime('%Y-%m-%d %H:%M:%S') if hasattr(result.get('timestamp', None), 'strftime') else str(result.get('timestamp', 'N/A')),
                'response_time': f"{result.get('response_time', 0):.2f}s",
                'additional_info': result.get('additional_info', {})
            }
            
            if 'database_type' in result:
                detailed_result['database_type'] = result['database_type']
            if 'xss_type' in result:
                detailed_result['xss_type'] = result['xss_type']
            if 'injection_type' in result:
                detailed_result['injection_type'] = result['injection_type']
            if 'os_type' in result:
                detailed_result['os_type'] = result['os_type']
            
            detailed_results.append(detailed_result)
        
        return detailed_results
    
    def _get_vulnerability_types(self, vulnerable_results: List[Dict]) -> Dict[str, int]:
        """Get distribution of vulnerability types"""
        types = {}
        for result in vulnerable_results:
            vuln_type = result.get('vulnerability_type', 'Unknown')
            types[vuln_type] = types.get(vuln_type, 0) + 1
        return types
    
    def _get_database_distribution(self, vulnerable_results: List[Dict]) -> Dict[str, int]:
        """Get distribution of database types (for SQLi)"""
        databases = {}
        for result in vulnerable_results:
            db_type = result.get('database_type')
            if db_type:
                databases[db_type] = databases.get(db_type, 0) + 1
        return databases
    
    def _get_payload_distribution(self, vulnerable_results: List[Dict]) -> Dict[str, int]:
        """Get distribution of successful payload categories"""
        payloads = {}
        for result in vulnerable_results:
            payload_category = result.get('additional_info', {}).get('payload_category', 'unknown')
            payloads[payload_category] = payloads.get(payload_category, 0) + 1
        return payloads
    
    def _get_confidence_stats(self, vulnerable_results: List[Dict]) -> Dict[str, Any]:
        """Get confidence score statistics for vulnerabilities"""
        if not vulnerable_results:
            return {}
        
        confidence_scores = []
        for result in vulnerable_results:
            confidence_str = result.get('additional_info', {}).get('confidence_score', '')
            if confidence_str and '%' in confidence_str:
                try:
                    confidence = float(confidence_str.replace('%', ''))
                    confidence_scores.append(confidence)
                except (ValueError, TypeError):
                    continue
        
        if not confidence_scores:
            return {}
        
        return {
            'average_confidence': f"{sum(confidence_scores) / len(confidence_scores):.1f}%",
            'highest_confidence': f"{max(confidence_scores):.1f}%",
            'lowest_confidence': f"{min(confidence_scores):.1f}%",
            'high_confidence_count': len([c for c in confidence_scores if c >= 80]),
            'medium_confidence_count': len([c for c in confidence_scores if 50 <= c < 80]),
            'low_confidence_count': len([c for c in confidence_scores if c < 50])
        }
    
    def _generate_remediation_guide(self, scan_type: str) -> Dict[str, Any]:
        """Generate detailed remediation guide"""
        guides = {
            'sqli': {
                'priority': 'CRITICAL',
                'immediate_steps': [
                    'Disable or restrict access to vulnerable endpoints',
                    'Review and patch all SQL query implementations',
                    'Implement parameterized queries immediately'
                ],
                'long_term_steps': [
                    'Implement comprehensive input validation framework',
                    'Deploy Web Application Firewall (WAF)',
                    'Regular security testing and code reviews',
                    'Database security hardening'
                ],
                'code_examples': [
                    {
                        'language': 'Python',
                        'vulnerable': "query = f'SELECT * FROM users WHERE id = {user_id}'",
                        'secure': "query = 'SELECT * FROM users WHERE id = %s'; cursor.execute(query, (user_id,))"
                    }
                ]
            },
            'xss': {
                'priority': 'HIGH',
                'immediate_steps': [
                    'Implement output encoding for all user content',
                    'Deploy Content Security Policy (CSP) headers',
                    'Review and fix input validation'
                ],
                'long_term_steps': [
                    'Implement XSS prevention framework',
                    'Regular security training for developers',
                    'Automated XSS testing in CI/CD pipeline'
                ],
                'code_examples': [
                    {
                        'language': 'JavaScript',
                        'vulnerable': "element.innerHTML = userInput",
                        'secure': "element.textContent = userInput"
                    }
                ]
            },
            'crlf': {
                'priority': 'MEDIUM',
                'immediate_steps': [
                    'Implement CRLF character filtering',
                    'Review header manipulation code',
                    'Validate all redirect parameters'
                ],
                'long_term_steps': [
                    'Use secure HTTP libraries',
                    'Implement strict header validation',
                    'Regular security assessments'
                ]
            },
            'cmdi': {
                'priority': 'CRITICAL',
                'immediate_steps': [
                    'Remove or secure command execution functionality',
                    'Implement strict input validation',
                    'Use secure APIs instead of shell commands'
                ],
                'long_term_steps': [
                    'Application sandboxing and containerization',
                    'Principle of least privilege implementation',
                    'Regular security monitoring and logging'
                ]
            }
        }
        
        return guides.get(scan_type, {
            'priority': 'MEDIUM',
            'immediate_steps': ['Review and fix identified vulnerabilities'],
            'long_term_steps': ['Implement security best practices']
        })
    
    def _get_methodology_description(self, scan_type: str) -> str:
        """Get methodology description for scan type"""
        methodologies = {
            'sqli': "This scan tested for SQL injection vulnerabilities using error-based detection techniques. Multiple payloads were tested against query parameters to identify database errors and injection points.",
            'xss': "This scan tested for Cross-Site Scripting vulnerabilities using reflection-based detection. Various XSS payloads were tested to identify script injection possibilities.",
            'crlf': "This scan tested for CRLF injection vulnerabilities by injecting carriage return and line feed characters to identify HTTP header manipulation possibilities.",
            'cmdi': "This scan tested for Command Injection vulnerabilities using output-based and time-based detection techniques to identify operating system command execution."
        }
        
        return methodologies.get(scan_type, "Comprehensive security vulnerability testing was performed using automated scanning techniques.")
    
    def _get_references(self, scan_type: str) -> List[str]:
        """Get relevant security references"""
        references = {
            'sqli': [
                "OWASP Top 10 2021 - A03 Injection",
                "OWASP SQL Injection Prevention Cheat Sheet",
                "CWE-89: Improper Neutralization of Special Elements used in an SQL Command",
                "NIST SP 800-53 - SI-10 Information Input Validation"
            ],
            'xss': [
                "OWASP Top 10 2021 - A03 Injection", 
                "OWASP XSS Prevention Cheat Sheet",
                "CWE-79: Improper Neutralization of Input During Web Page Generation",
                "Content Security Policy Level 3 - W3C"
            ],
            'crlf': [
                "CWE-93: Improper Neutralization of CRLF Sequences",
                "OWASP Testing Guide - Testing for HTTP Response Splitting",
                "RFC 7230 - HTTP/1.1 Message Syntax and Routing"
            ],
            'cmdi': [
                "OWASP Top 10 2021 - A03 Injection",
                "CWE-78: Improper Neutralization of Special Elements used in an OS Command",
                "NIST SP 800-53 - SI-10 Information Input Validation"
            ]
        }
        
        return references.get(scan_type, [
            "OWASP Top 10 2021",
            "SANS Top 25 Most Dangerous Software Errors",
            "NIST Cybersecurity Framework"
        ])
    
    def _format_technical_details(self, scan_results: List[Dict]) -> Dict[str, Any]:
        """Format technical details for appendix"""
        return {
            'total_requests_sent': len(scan_results),
            'average_response_time': f"{sum(r.get('response_time', 0) for r in scan_results) / len(scan_results):.2f}s" if scan_results else "0s",
            'unique_urls_tested': len(set(r.get('url', '') for r in scan_results)),
            'error_count': len([r for r in scan_results if r.get('error_message')]),
            'scan_coverage': "100% of provided URLs were tested"
        }
    
    def generate_pdf_report(self, report_data: Dict[str, Any], output_file: str):
        """
        Generate actual PDF report using ReportLab
        """
        try:
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.lib import colors
            from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
            
            doc = SimpleDocTemplate(output_file, pagesize=letter)
            styles = getSampleStyleSheet()
            story = []
            
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                spaceAfter=30,
                alignment=TA_CENTER,
                textColor=colors.darkblue
            )
            
            heading_style = ParagraphStyle(
                'CustomHeading',
                parent=styles['Heading2'],
                fontSize=16,
                spaceAfter=12,
                textColor=colors.darkred
            )
            
            subheading_style = ParagraphStyle(
                'CustomSubHeading',
                parent=styles['Heading3'],
                fontSize=14,
                spaceAfter=8,
                textColor=colors.darkblue
            )
            
            story.append(Paragraph(report_data['report_info']['title'], title_style))
            story.append(Spacer(1, 20))
            
            info_data = [
                ['Generated:', report_data['report_info']['generated_at']],
                ['Scanner Version:', report_data['report_info']['scanner_version']],
                ['Target URL:', report_data['report_info']['target_url']],
                ['Scan Type:', report_data['report_info']['scan_type']],
                ['Total URLs Scanned:', str(report_data['report_info']['total_urls_scanned'])],
                ['Vulnerable URLs:', str(report_data['report_info']['vulnerable_urls'])],
                ['Overall Risk Level:', report_data['report_info']['overall_risk']]
            ]
            
            info_table = Table(info_data, colWidths=[2*inch, 4*inch])
            info_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('BACKGROUND', (1, 0), (1, -1), colors.beige),
            ]))
            
            story.append(info_table)
            story.append(Spacer(1, 30))
            
            story.append(Paragraph("Executive Summary", heading_style))
            
            exec_summary = report_data.get('executive_summary', {})
            risk_level = exec_summary.get('risk_level', 'Unknown')
            
            risk_color = "red" if risk_level in ['CRITICAL', 'HIGH'] else "orange" if risk_level == 'MEDIUM' else "green"
            
            story.append(Paragraph(f"<b>Overall Risk Level: <font color='{risk_color}'>{risk_level}</font></b>", styles['Normal']))
            story.append(Spacer(1, 12))
            
            if exec_summary.get('key_findings'):
                story.append(Paragraph("<b>Key Findings:</b>", styles['Normal']))
                for finding in exec_summary['key_findings']:
                    story.append(Paragraph(f"• {finding}", styles['Normal']))
                story.append(Spacer(1, 12))
            
            if report_data.get('detailed_results'):
                story.append(Paragraph("Vulnerability Details", heading_style))
                
                vuln_data = [['URL', 'Type', 'Risk Level', 'Payload']]
                
                for vuln in report_data['detailed_results'][:10]:  # Show first 10
                    # Use full URLs and payloads - let ReportLab handle wrapping
                    url = vuln.get('url', 'N/A')
                    payload = vuln.get('payload', 'N/A')
                    
                    # Escape HTML characters to prevent ReportLab parsing errors
                    import html
                    escaped_url = html.escape(url)
                    escaped_payload = html.escape(payload)
                    
                    url_para = Paragraph(escaped_url, styles['Normal'])
                    payload_para = Paragraph(escaped_payload, styles['Normal'])
                        
                    vuln_data.append([
                        url_para,
                        vuln.get('vulnerability_type', 'N/A'),
                        vuln.get('risk_level', 'N/A'),
                        payload_para
                    ])
                
                vuln_table = Table(vuln_data, colWidths=[2.5*inch, 1.0*inch, 0.8*inch, 2.7*inch])
                vuln_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),  # Left align for better readability
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),   # Top align for multi-line content
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 9),      # Slightly smaller font for headers
                    ('FONTSIZE', (0, 1), (-1, -1), 8),     # Smaller font for content
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('TOPPADDING', (0, 1), (-1, -1), 8),   # More padding for readability
                    ('BOTTOMPADDING', (0, 1), (-1, -1), 8),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('WORDWRAP', (0, 0), (-1, -1), 'CJK'),  # Enable word wrapping
                ]))
                
                story.append(vuln_table)
                story.append(Spacer(1, 20))
                
                # Add detailed payload section for vulnerabilities found
                if len(report_data['detailed_results']) > 0:
                    story.append(Paragraph("Complete Payload Details", heading_style))
                    story.append(Spacer(1, 10))
                    
                    for i, vuln in enumerate(report_data['detailed_results'][:5], 1):  # Show first 5
                        vuln_title = f"{i}. {vuln.get('vulnerability_type', 'Unknown')} - {vuln.get('risk_level', 'Unknown')} Risk"
                        story.append(Paragraph(vuln_title, subheading_style))
                        
                        import html
                        escaped_url = html.escape(vuln.get('url', 'N/A'))
                        story.append(Paragraph(f"<b>Target URL:</b> {escaped_url}", styles['Normal']))
                        
                        # Complete payload (properly escaped for PDF)
                        payload = vuln.get('payload', 'N/A')
                        escaped_payload = html.escape(payload)
                        
                        if len(payload) > 100:
                            # For very long payloads, use a smaller font and code style
                            story.append(Paragraph(f"<b>Complete Payload:</b>", styles['Normal']))
                            story.append(Paragraph(f"<font name='Courier' size='8'>{escaped_payload}</font>", styles['Normal']))
                        else:
                            story.append(Paragraph(f"<b>Payload:</b> <font name='Courier'>{escaped_payload}</font>", styles['Normal']))
                        
                        additional_info = vuln.get('additional_info', {})
                        if additional_info.get('confidence'):
                            story.append(Paragraph(f"<b>Confidence:</b> {additional_info['confidence']}", styles['Normal']))
                        
                        story.append(Spacer(1, 15))
                    
                    if len(report_data['detailed_results']) > 5:
                        story.append(Paragraph(f"<i>... and {len(report_data['detailed_results']) - 5} more vulnerabilities. See complete results in text report.</i>", styles['Normal']))
                        story.append(Spacer(1, 15))
            
            if exec_summary.get('recommendations') and report_data.get('detailed_results') and len(report_data['detailed_results']) > 0:
                story.append(Paragraph("Recommendations", heading_style))
                for recommendation in exec_summary['recommendations']:
                    story.append(Paragraph(f"• {recommendation}", styles['Normal']))
                story.append(Spacer(1, 12))
            
            doc.build(story)
            print(f"✅ PDF report successfully generated: {output_file}")
            return True
            
        except ImportError:
            print("❌ ReportLab not installed. Installing...")
            import subprocess
            import sys
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", "reportlab", "pillow"])
                print("✅ ReportLab installed! Please run the report generation again.")
                return False
            except Exception as e:
                print(f"❌ Failed to install ReportLab: {e}")
                return self._generate_fallback_report(report_data, output_file)
        
        except Exception as e:
            print(f"❌ Error generating PDF: {e}")
            return self._generate_fallback_report(report_data, output_file)
    
    def _generate_fallback_report(self, report_data: Dict[str, Any], output_file: str) -> bool:
        """Generate fallback text report if PDF generation fails"""
        try:
            pdf_content = self._generate_text_report(report_data)
            
            txt_file = output_file.replace('.pdf', '_report.txt')
            with open(txt_file, 'w') as f:
                f.write(pdf_content)
            
            json_file = output_file.replace('.pdf', '_data.json')
            with open(json_file, 'w') as f:
                json.dump(report_data, f, indent=2, default=str)
            
            print(f"📄 Text report saved: {txt_file}")
            print(f"📊 Data saved: {json_file}")
            print("💡 Install 'reportlab' for PDF generation: pip install reportlab pillow")
            return True
            
        except Exception as e:
            print(f"❌ Error generating fallback report: {e}")
            return False
    
    def _generate_text_report(self, report_data: Dict[str, Any]) -> str:
        """Generate text-based report content"""
        content = []
        
        content.append("=" * 80)
        content.append(report_data['report_info']['title'].upper())
        content.append("=" * 80)
        content.append(f"Generated: {report_data['report_info']['generated_at']}")
        content.append(f"Scanner: {report_data['report_info']['scanner_version']}")
        content.append(f"Target: {report_data['report_info']['target_url']}")
        content.append(f"Overall Risk: {report_data['report_info']['overall_risk']}")
        content.append("")
        
        content.append("EXECUTIVE SUMMARY")
        content.append("-" * 40)
        for finding in report_data['executive_summary']['key_findings']:
            content.append(f"• {finding}")
        content.append("")
        
        content.append("RECOMMENDATIONS")
        content.append("-" * 40)
        for rec in report_data['executive_summary']['recommendations']:
            content.append(f"• {rec}")
        content.append("")
        
        if report_data['detailed_results']:
            content.append("DETAILED VULNERABILITY FINDINGS")
            content.append("-" * 40)
            for result in report_data['detailed_results']:
                content.append(f"{result['id']}. {result['vulnerability_type']} - {result['risk_level']} Risk")
                content.append(f"   URL: {result['url']}")
                content.append(f"   Payload: {result['payload']}")
                content.append(f"   Time: {result['timestamp']}")
                content.append("")
        
        content.append("SCAN STATISTICS")
        content.append("-" * 40)
        stats = report_data['statistics']
        content.append(f"Total Requests: {stats['total_requests']}")
        content.append(f"Success Rate: {stats['success_rate']}")
        content.append(f"Vulnerabilities Found: {report_data['report_info']['total_vulnerabilities']}")
        content.append("")
        
        return "\n".join(content)


if __name__ == "__main__":
    generator = ReportGenerator()
    
    mock_results = [
        {
            'url': 'http://example.com/test.php?id=1',
            'is_vulnerable': True,
            'vulnerability_type': 'SQL Injection',
            'database_type': 'MySQL',
            'payload': "' OR 1=1--",
            'response_time': 1.23,
            'risk_level': 'High',
            'timestamp': datetime.now(),
            'additional_info': {'payload_category': 'boolean'}
        }
    ]
    
    report_data = generator.generate_pdf_report_data(
        mock_results, 
        scan_type='sqli', 
        target_url='http://example.com'
    )
    
    generator.generate_pdf_report(report_data, 'test_report.pdf')
    print("Test report generated!")
