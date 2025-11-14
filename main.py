#!/usr/bin/env python3

import os
import sys
import json
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import threading
from pathlib import Path

import tkinter as tk 
from tkinter import filedialog, messagebox

try:
    import customtkinter as ctk
    MODERN_GUI_AVAILABLE = True
    ctk.set_appearance_mode("light")  # "light" or "dark"
    ctk.set_default_color_theme("blue")  # "blue", "green", "dark-blue"
except ImportError:
    MODERN_GUI_AVAILABLE = False

from scanners.unified_crawler import UnifiedCrawler
from scanners.sqli_scanner import SQLiScanner
from scanners.xss_scanner import XSSScanner
from scanners.crlf_scanner import CRLFScanner
from scanners.cmd_injection_scanner import CmdInjectionScanner
from scanners.report_generator import ReportGenerator


class ModernSecurityScannerGUI:
    """Beautiful Modern GUI for Web Security Scanner"""
    
    def __init__(self):        
        if MODERN_GUI_AVAILABLE:
            self.root = ctk.CTk()
        else:
            self.root = tk.Tk()
        
        self.current_scan_type = tk.StringVar(value="sqli")
        self.target_url = tk.StringVar()
        self.crawl_enabled = tk.BooleanVar(value=True)
        self.dark_mode = tk.BooleanVar(value=False)
        self.exploitation_mode = tk.BooleanVar(value=False)
        self.scanning = False
        self.scan_results = []
        self.live_vulnerabilities = []  # For real-time feed
        
        self.scan_start_time = 0
        self.scan_duration = 0
        self.crawled_urls = []
        
        self.crawler = UnifiedCrawler()
        self.sqli_scanner = SQLiScanner()
        self.xss_scanner = XSSScanner()
        self.crlf_scanner = CRLFScanner()
        self.cmd_scanner = CmdInjectionScanner()
        self.report_generator = ReportGenerator()
        
        if MODERN_GUI_AVAILABLE:
            self.setup_modern_gui()
        else:
            print("❌ CustomTkinter not available. Please install it:")
            print("pip install customtkinter")
            sys.exit(1)
    
    def setup_modern_gui(self):
        """Setup modern GUI with CustomTkinter"""
        self.root.title("🛡️ Web Application Scanner Beta")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)
        
        self.colors = {
            'primary': '#2196F3',
            'secondary': '#FFC107',
            'success': '#4CAF50',
            'danger': '#F44336',
            'warning': '#FF9800',
            'info': '#00BCD4',
            'dark': '#212121',
            'light': '#F5F5F5'
        }
        
        self.create_modern_header()
        self.create_modern_main_content()
        self.create_modern_footer()
    
    def create_modern_header(self):
        """Create modern header with gradient effect"""
        header_frame = ctk.CTkFrame(self.root, height=80, corner_radius=0)
        header_frame.pack(fill="x", padx=0, pady=0)
        
        title_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        title_frame.pack(fill="x", padx=20, pady=15)
        
        title_label = ctk.CTkLabel(
            title_frame,
            text="🛡️ Web Application Scanner Beta",
            font=ctk.CTkFont(size=28, weight="bold"),
            text_color="#1976D2"
        )
        title_label.pack(side="left")
        
        self.dark_mode_button = ctk.CTkButton(
            title_frame,
            text="🌙",
            font=ctk.CTkFont(size=16),
            width=40,
            height=30,
            command=self.toggle_dark_mode
        )
        self.dark_mode_button.pack(side="right", padx=(10, 0))
        
        self.status_indicator = ctk.CTkLabel(
            title_frame,
            text="● Ready",
            font=ctk.CTkFont(size=14),
            text_color="#4CAF50"
        )
        self.status_indicator.pack(side="right", padx=(0, 20))
    
    def create_modern_main_content(self):
        """Create modern main content area"""
        main_container = ctk.CTkFrame(self.root, fg_color="transparent")
        main_container.pack(fill="both", expand=True, padx=20, pady=10)
        
        left_frame = ctk.CTkScrollableFrame(main_container)
        left_frame.pack(side="left", fill="both", expand=True, padx=(0, 10))
        
        right_frame = ctk.CTkFrame(main_container, width=350)
        right_frame.pack(side="right", fill="y", padx=(10, 0))
        right_frame.pack_propagate(False)
        
        self.create_scanner_cards(left_frame)
        
        self.create_modern_url_input(left_frame)
        

        
        self.create_modern_controls(left_frame)
        
        self.create_modern_results_area(left_frame)
        
        self.create_live_vulnerability_feed(right_frame)
        self.create_exploitation_panel(right_frame)
    
    def create_scanner_cards(self, parent):
        """Create beautiful scanner selection cards"""
        cards_frame = ctk.CTkFrame(parent)
        cards_frame.pack(fill="x", pady=(0, 20))
        
        title_label = ctk.CTkLabel(
            cards_frame,
            text="🎯 Select Vulnerability Scanner",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        title_label.pack(pady=(20, 15))
        
        cards_container = ctk.CTkFrame(cards_frame, fg_color="transparent")
        cards_container.pack(fill="x", padx=20, pady=(0, 20))
        
        scanners = [
            ("sqli", "🗄️", "SQL Injection", "Database injection vulnerabilities", "#E53E3E"),
            ("xss", "⚡", "Cross-Site Scripting", "Script injection vulnerabilities", "#DD6B20"),
            ("crlf", "📄", "CRLF Injection", "HTTP response splitting", "#0078D4"),
            ("cmd", "💻", "Command Injection", "OS command injection", "#6B46C1"),
            ("future", "🚧", "Advanced Payloads", "In Development - Future scanner", "#9CA3AF")
        ]
        
        for i, (value, icon, title, desc, color) in enumerate(scanners):
            card = self.create_scanner_card(cards_container, value, icon, title, desc, color)
            row = i // 3
            col = i % 3
            card.grid(row=row, column=col, padx=10, pady=10, sticky="ew")
        
        for i in range(3):
            cards_container.grid_columnconfigure(i, weight=1)
    
    def create_scanner_card(self, parent, value, icon, title, desc, color):
        """Create individual scanner card"""
        card = ctk.CTkFrame(parent, height=120, corner_radius=15)
        
        content_frame = ctk.CTkFrame(card, fg_color="transparent")
        content_frame.pack(fill="both", expand=True, padx=15, pady=15)
        
        header_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        header_frame.pack(fill="x")
        
        icon_label = ctk.CTkLabel(
            header_frame,
            text=icon,
            font=ctk.CTkFont(size=32)
        )
        icon_label.pack(side="left")
        
        title_label = ctk.CTkLabel(
            header_frame,
            text=title,
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=color
        )
        title_label.pack(side="left", padx=(10, 0))
        
        desc_label = ctk.CTkLabel(
            content_frame,
            text=desc,
            font=ctk.CTkFont(size=12),
            text_color="gray"
        )
        desc_label.pack(anchor="w", pady=(5, 0))
        
        if value == "future":
            radio = ctk.CTkRadioButton(
                content_frame,
                text="🚧 Coming Soon",
                variable=self.current_scan_type,
                value=value,
                radiobutton_width=20,
                radiobutton_height=20,
                state="disabled",
                font=ctk.CTkFont(size=10),
                text_color="gray"
            )
        else:
            radio = ctk.CTkRadioButton(
                content_frame,
                text="",
                variable=self.current_scan_type,
                value=value,
                radiobutton_width=20,
                radiobutton_height=20
            )
        radio.pack(anchor="se", side="bottom")
        
        return card
    
    def create_modern_url_input(self, parent):
        """Create modern URL input section"""
        url_frame = ctk.CTkFrame(parent)
        url_frame.pack(fill="x", pady=(0, 20))
        
        title_label = ctk.CTkLabel(
            url_frame,
            text="🎯 Target Configuration",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        title_label.pack(pady=(20, 15))
        
        input_frame = ctk.CTkFrame(url_frame, fg_color="transparent")
        input_frame.pack(fill="x", padx=20, pady=(0, 15))
        
        url_label = ctk.CTkLabel(input_frame, text="Target URL:", font=ctk.CTkFont(size=14, weight="bold"))
        url_label.pack(anchor="w", pady=(0, 5))
        
        self.url_entry = ctk.CTkEntry(
            input_frame,
            textvariable=self.target_url,
            height=40,
            placeholder_text="https://example.com/page?param=value",
            font=ctk.CTkFont(size=12)
        )
        self.url_entry.pack(fill="x", pady=(0, 10))
        
        options_frame = ctk.CTkFrame(input_frame, fg_color="transparent")
        options_frame.pack(fill="x")
        
        self.crawl_checkbox = ctk.CTkCheckBox(
            options_frame,
            text="🕷️ Enable intelligent crawling (find more URLs)",
            variable=self.crawl_enabled,
            font=ctk.CTkFont(size=12)
        )
        self.crawl_checkbox.pack(anchor="w")
        

    
    def toggle_dark_mode(self):
        """Toggle between light and dark mode"""
        if self.dark_mode.get():
            ctk.set_appearance_mode("light")
            self.dark_mode_button.configure(text="🌙")
            self.dark_mode.set(False)
        else:
            ctk.set_appearance_mode("dark")
            self.dark_mode_button.configure(text="☀️")
            self.dark_mode.set(True)
    
    def create_live_vulnerability_feed(self, parent):
        """Create real-time vulnerability feed panel"""
        feed_frame = ctk.CTkFrame(parent)
        feed_frame.pack(fill="x", pady=(0, 20))
        
        title_label = ctk.CTkLabel(
            feed_frame,
            text="🚨 Live Vulnerability Feed",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        title_label.pack(pady=(15, 10))
        
        self.live_feed = ctk.CTkTextbox(
            feed_frame,
            height=350,
            font=ctk.CTkFont(family="Consolas", size=12, weight="normal"),
            text_color="#E8E8E8",
            fg_color="#1A1A1A"
        )
        self.live_feed.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        
        welcome_feed = """🔍 Real-time Vulnerability Detection

⏳ Waiting for scan to start...

Features:
• Live vulnerability notifications
• Risk severity indicators  
• Instant threat assessment
• Real-time confidence scoring

Ready to detect threats! 🛡️"""
        
        self.live_feed.insert("1.0", welcome_feed)
    
    def create_exploitation_panel(self, parent):
        """Create exploitation mode panel (coming soon)"""
        exploit_frame = ctk.CTkFrame(parent)
        exploit_frame.pack(fill="both", expand=True)
        
        title_label = ctk.CTkLabel(
            exploit_frame,
            text="⚔️ Exploitation Mode",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        title_label.pack(pady=(15, 10))
        
        coming_soon_frame = ctk.CTkFrame(exploit_frame, fg_color="transparent")
        coming_soon_frame.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        
        icon_label = ctk.CTkLabel(
            coming_soon_frame,
            text="🚧",
            font=ctk.CTkFont(size=48)
        )
        icon_label.pack(pady=20)
        
        status_label = ctk.CTkLabel(
            coming_soon_frame,
            text="COMING SOON",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#FF9800"
        )
        status_label.pack()
        
        description = ctk.CTkLabel(
            coming_soon_frame,
            text="Advanced exploitation capabilities:\n\n• Automated payload generation\n• Exploit chain discovery\n• Post-exploitation modules\n• Privilege escalation detection\n• Advanced evasion techniques",
            font=ctk.CTkFont(size=11),
            text_color="gray",
            justify="left"
        )
        description.pack(pady=15)
        
        self.exploit_toggle = ctk.CTkCheckBox(
            coming_soon_frame,
            text="🔥 Enable Exploitation Mode",
            variable=self.exploitation_mode,
            font=ctk.CTkFont(size=12),
            state="disabled"
        )
        self.exploit_toggle.pack(pady=10)
    
    def create_modern_controls(self, parent):
        """Create modern control buttons"""
        controls_frame = ctk.CTkFrame(parent, fg_color="transparent")
        controls_frame.pack(fill="x", pady=(0, 20))
        
        self.scan_button = ctk.CTkButton(
            controls_frame,
            text="🚀 Start Security Scan",
            font=ctk.CTkFont(size=16, weight="bold"),
            height=50,
            command=self.start_scan,
            fg_color="#4CAF50",
            hover_color="#45A049"
        )
        self.scan_button.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        self.stop_button = ctk.CTkButton(
            controls_frame,
            text="⏹️ Stop",
            font=ctk.CTkFont(size=14),
            height=50,
            width=100,
            command=self.stop_scan,
            fg_color="#F44336",
            hover_color="#D32F2F",
            state="disabled"
        )
        self.stop_button.pack(side="left", padx=(0, 10))
        
        self.export_button = ctk.CTkButton(
            controls_frame,
            text="📄 Export PDF",
            font=ctk.CTkFont(size=14),
            height=50,
            width=120,
            command=self.export_results,
            state="disabled"
        )
        self.export_button.pack(side="left")
    
    def create_modern_results_area(self, parent):
        """Create modern results display area"""
        results_frame = ctk.CTkFrame(parent)
        results_frame.pack(fill="both", expand=True)
        
        header_frame = ctk.CTkFrame(results_frame, fg_color="transparent")
        header_frame.pack(fill="x", padx=20, pady=(20, 10))
        
        results_title = ctk.CTkLabel(
            header_frame,
            text="📊 Scan Results",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        results_title.pack(side="left")
        
        progress_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        progress_frame.pack(side="right")
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ctk.CTkProgressBar(
            progress_frame,
            variable=self.progress_var,
            width=250,
            height=25,
            progress_color="#4CAF50",
            corner_radius=10
        )
        self.progress_bar.pack(side="top", pady=(0, 5))
        
        self.progress_percentage = ctk.CTkLabel(
            progress_frame,
            text="0%",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="#4CAF50"
        )
        self.progress_percentage.pack(side="top")
        
        self.progress_label = ctk.CTkLabel(
            header_frame,
            text="Ready to scan",
            font=ctk.CTkFont(size=12)
        )
        self.progress_label.pack(side="right", padx=(10, 0))
        
        self.results_text = ctk.CTkTextbox(
            results_frame,
            font=ctk.CTkFont(family="Courier", size=11)
        )
        self.results_text.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
    def create_modern_footer(self):
        """Create modern footer"""
        footer_frame = ctk.CTkFrame(self.root, height=40, corner_radius=0)
        footer_frame.pack(fill="x", side="bottom")
        
        footer_label = ctk.CTkLabel(
            footer_frame,
            text="🛡️ Web Application Scanner Beta v2.0 | Advanced Cybersecurity Research Tool",
            font=ctk.CTkFont(size=10),
            text_color="gray"
        )
        footer_label.pack(pady=10)
    
    def start_scan(self):
        """Start the security scan"""
        if not self.target_url.get():
            if MODERN_GUI_AVAILABLE:
                self.show_modern_error("Please enter a target URL")
            else:
                messagebox.showerror("Error", "Please enter a target URL")
            return
        
        if self.current_scan_type.get() == "future":
            if MODERN_GUI_AVAILABLE:
                self.show_modern_error("🚧 This scanner is still in development!\n\nPlease select one of the available scanners:\n• SQL Injection\n• Cross-Site Scripting\n• CRLF Injection\n• Command Injection")
            else:
                messagebox.showerror("Error", "This scanner is still in development!")
            return
        
        self.scan_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.export_button.configure(state="disabled")  # Disable export during scan
        self.scanning = True
        self.progress_var.set(0)
        self._results_displayed = False  # Reset results display flag
        
        self.live_vulnerabilities = []
        self.live_feed.delete("1.0", tk.END)
        self.live_feed.insert("1.0", "🚀 Starting security scan...\n\n")
        
        self.results_text.delete("1.0", tk.END)
        
        scan_thread = threading.Thread(target=self.run_scan, daemon=True)
        scan_thread.start()
    
    def show_modern_error(self, message):
        """Show modern error dialog"""
        error_window = ctk.CTkToplevel(self.root)
        error_window.title("Error")
        error_window.geometry("400x150")
        error_window.transient(self.root)
        error_window.grab_set()
        
        error_window.update_idletasks()
        x = (error_window.winfo_screenwidth() // 2) - (400 // 2)
        y = (error_window.winfo_screenheight() // 2) - (150 // 2)
        error_window.geometry(f"400x150+{x}+{y}")
        
        # Error content
        ctk.CTkLabel(error_window, text="❌ Error", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=20)
        ctk.CTkLabel(error_window, text=message).pack(pady=10)
        ctk.CTkButton(error_window, text="OK", command=error_window.destroy).pack(pady=10)
    
    def run_scan(self):
        """Run the actual security scan"""
        import time
        self.scan_start_time = time.time()
        
        try:
            scan_type = self.current_scan_type.get()
            target_url = self.target_url.get()
            
            self.update_status("🔍 Starting scan...")
            
            urls = [target_url]
            self.crawled_urls = []  # Reset crawled URLs
            
            if self.crawl_enabled.get():
                self.update_status("🕷️ Crawling for more URLs...")
                
                def update_crawl_feed():
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    self.live_feed.insert(tk.END, f"🕷️ [{timestamp}] Starting web crawling...\n")
                    self.live_feed.insert(tk.END, f"🎯 [{timestamp}] Target: {target_url}\n")
                    self.live_feed.see(tk.END)
                self.root.after(0, update_crawl_feed)
                
                crawled_urls_raw = self.crawler.crawl_website(target_url)
                self.crawled_urls = crawled_urls_raw  # Store all crawled URLs
                additional_urls = [url for url in crawled_urls_raw if '?' in url and '=' in url]
                
                unique_additional_urls = []
                for url in additional_urls[:15]:  # Limit to 15 URLs
                    if url not in urls and url not in unique_additional_urls:
                        unique_additional_urls.append(url)
                
                urls.extend(unique_additional_urls)
                
                def update_crawled_feed():
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    self.live_feed.insert(tk.END, f"📊 [{timestamp}] Crawling complete!\n")
                    self.live_feed.insert(tk.END, f"🔍 [{timestamp}] Found {len(crawled_urls_raw)} total URLs\n")
                    self.live_feed.insert(tk.END, f"🎯 [{timestamp}] Selected {len(additional_urls)} URLs with parameters\n")
                    self.live_feed.insert(tk.END, f"✅ [{timestamp}] Added {len(unique_additional_urls)} unique URLs (duplicates removed)\n")
                    
                    if len(crawled_urls_raw) > 0:
                        self.live_feed.insert(tk.END, f"📝 [{timestamp}] All crawled URLs:\n")
                        for i, url in enumerate(crawled_urls_raw[:10], 1):  # Show first 10
                            has_params = '✓' if ('?' in url and '=' in url) else '✗'
                            self.live_feed.insert(tk.END, f"   {i}. {has_params} {url[:60]}{'...' if len(url) > 60 else ''}\n")
                        if len(crawled_urls_raw) > 10:
                            self.live_feed.insert(tk.END, f"   ... and {len(crawled_urls_raw) - 10} more URLs\n")
                    
                    if len(unique_additional_urls) > 0:
                        self.live_feed.insert(tk.END, f"📋 [{timestamp}] Unique URLs to scan (with parameters):\n")
                        for i, url in enumerate(unique_additional_urls[:5], 1):  # Show first 5
                            self.live_feed.insert(tk.END, f"   {i}. {url[:70]}{'...' if len(url) > 70 else ''}\n")
                        if len(unique_additional_urls) > 5:
                            self.live_feed.insert(tk.END, f"   ... and {len(unique_additional_urls) - 5} more URLs\n")
                    else:
                        self.live_feed.insert(tk.END, f"⚠️ [{timestamp}] No unique crawled URLs with parameters found!\n")
                        
                    self.live_feed.insert(tk.END, f"{'='*60}\n")
                    self.live_feed.see(tk.END)
                self.root.after(0, update_crawled_feed)
                
                self.update_progress(0.2)
            
            self.update_status(f"🎯 Scanning {len(urls)} unique URLs total ({len(urls)-1} unique crawled + 1 target)")
            
            def update_scan_list():
                timestamp = datetime.now().strftime("%H:%M:%S")
                self.live_feed.insert(tk.END, f"🎯 [{timestamp}] URLS TO BE SCANNED ({len(urls)} total):\n")
                for i, url in enumerate(urls, 1):
                    self.live_feed.insert(tk.END, f"   {i}. {url[:70]}{'...' if len(url) > 70 else ''}\n")
                self.live_feed.insert(tk.END, f"{'='*60}\n")
                self.live_feed.see(tk.END)
            self.root.after(0, update_scan_list)
            
            if scan_type == "sqli":
                scanner = self.sqli_scanner
                self.update_status("🗄️ Running SQL Injection scan...")
            elif scan_type == "xss":
                scanner = self.xss_scanner
                self.update_status("⚡ Running XSS scan...")
            elif scan_type == "crlf":
                scanner = self.crlf_scanner
                self.update_status("📄 Running CRLF Injection scan...")
            elif scan_type == "cmd":
                scanner = self.cmd_scanner
                self.update_status("💻 Running Command Injection scan...")
            
            def live_status_callback(message):
                self.update_status(message)
                if "Found SQLi" in message or "Found XSS" in message or "Found CRLF" in message or "Found Command" in message:
                    vuln_data = {
                        'is_vulnerable': True,
                        'vulnerability_type': scan_type.upper(),
                        'url': message.split(' in ')[-1].split(' ')[0] if ' in ' in message else target_url,
                        'risk_level': 'High',
                        'payload': 'Detection payload'
                    }
                    
                    # Extract database type for SQLi
                    if "DB:" in message:
                        db_type = message.split("DB: ")[-1].split(")")[0]
                        vuln_data['database_type'] = db_type
                    
                    if "Confidence:" in message:
                        confidence = message.split("Confidence: ")[-1].split("%")[0]
                        vuln_data['confidence_score'] = f"{confidence}%"
                    
                    self.add_live_vulnerability(vuln_data)
                else:
                    self.add_live_vulnerability({
                        'is_vulnerable': False,
                        'url': message.split('Scanning: ')[-1] if 'Scanning:' in message else ''
                    })
            
            results = scanner.scan_urls(
                urls,
                progress_callback=self.update_scan_progress,
                status_callback=live_status_callback
            )
            
            self.scan_results = results
            self.display_results(results)
            
            self.scan_duration = time.time() - self.scan_start_time
            
            self.export_button.configure(state="normal")
            
            self.update_status(f"✅ Scan completed in {self.scan_duration:.2f} seconds!")
            self.update_progress(1.0)
            
        except Exception as e:
            self.scan_duration = time.time() - self.scan_start_time if hasattr(self, 'scan_start_time') else 0
            self.update_status(f"❌ Scan failed: {str(e)}")
        finally:
            self.scan_button.configure(state="normal")
            self.stop_button.configure(state="disabled")
            if not self.scan_results:
                self.export_button.configure(state="disabled")
            self.scanning = False
    
    def add_live_vulnerability(self, vulnerability_data):
        """Add vulnerability to live feed in real-time"""
        def update_feed():
            timestamp = datetime.now().strftime("%H:%M:%S")
            
            if vulnerability_data.get('is_vulnerable', False):
                risk_level = vulnerability_data.get('risk_level', 'Unknown')
                vuln_type = vulnerability_data.get('vulnerability_type', 'Unknown')
                url = vulnerability_data.get('url', 'Unknown')
                
                if risk_level.lower() == 'critical':
                    icon = "🔴"
                elif risk_level.lower() == 'high':
                    icon = "🟠"
                elif risk_level.lower() == 'medium':
                    icon = "🟡"
                else:
                    icon = "🔵"
                
                feed_entry = f"\n{'='*50}\n"
                feed_entry += f"{icon} [{timestamp}] {risk_level.upper()} RISK DETECTED\n"
                feed_entry += f"{'='*50}\n"
                feed_entry += f"🎯 Vulnerability: {vuln_type}\n"
                feed_entry += f"🌐 Target URL: {url}\n"
                feed_entry += f"💉 Payload: {vulnerability_data.get('payload', 'N/A')}\n"
                
                # Add database info if available
                if vulnerability_data.get('database_type'):
                    feed_entry += f"🗄️ Database: {vulnerability_data.get('database_type')}\n"
                
                if vulnerability_data.get('confidence_score'):
                    feed_entry += f"🎯 Confidence: {vulnerability_data.get('confidence_score')}\n"
                
                feed_entry += f"{'='*50}\n"
                
                self.live_feed.insert(tk.END, feed_entry)
                self.live_feed.see(tk.END)
                
                self.live_vulnerabilities.append(vulnerability_data)
            else:
                url = vulnerability_data.get('url', 'Unknown')
                feed_entry = f"🔍 [{timestamp}] Scanning: {url[:60]}{'...' if len(url) > 60 else ''}\n"
                self.live_feed.insert(tk.END, feed_entry)
                self.live_feed.see(tk.END)
        
        self.root.after(0, update_feed)
    
    def update_status(self, message):
        """Update status label"""
        def update():
            self.progress_label.configure(text=message)
            if hasattr(self, 'status_indicator'):
                if "✅" in message:
                    self.status_indicator.configure(text="● Complete", text_color="#4CAF50")
                elif "❌" in message:
                    self.status_indicator.configure(text="● Error", text_color="#F44336")
                elif "🔍" in message or "🕷️" in message or "🎯" in message:
                    self.status_indicator.configure(text="● Scanning", text_color="#FF9800")
            
            if not hasattr(self, '_results_displayed') or not self._results_displayed:
                timestamp = datetime.now().strftime("%H:%M:%S")
                
                if "🔍 Starting scan" in message:
                    formatted_message = f"\n🚀 [{timestamp}] Initiating security scan...\n"
                elif "🕷️ Crawling" in message:
                    formatted_message = f"🕷️  [{timestamp}] Discovering additional URLs...\n"
                elif "🎯 Found" in message:
                    formatted_message = f"📊 [{timestamp}] {message.replace('🎯 ', '')}\n"
                elif any(scan_type in message for scan_type in ["🗄️", "⚡", "📄", "💻"]):
                    formatted_message = f"🔍 [{timestamp}] {message}\n"
                elif "✅ Scan completed" in message:
                    formatted_message = f"✅ [{timestamp}] Scan completed successfully!\n\n"
                    self._results_displayed = True  # Mark that results will be displayed
                elif "❌" in message:
                    formatted_message = f"❌ [{timestamp}] {message}\n"
                else:
                    formatted_message = f"ℹ️  [{timestamp}] {message}\n"
                
                self.results_text.insert(tk.END, formatted_message)
                self.results_text.see(tk.END)
        
        self.root.after(0, update)
    
    def update_progress(self, value):
        """Update progress bar with percentage display"""
        def update():
            self.progress_var.set(value)
            percentage = int(value * 100)
            self.progress_percentage.configure(text=f"{percentage}%")
            if percentage < 30:
                self.progress_percentage.configure(text_color="#FF9800")  # Orange
            elif percentage < 70:
                self.progress_percentage.configure(text_color="#2196F3")  # Blue
            else:
                self.progress_percentage.configure(text_color="#4CAF50")  # Green
        self.root.after(0, update)
    
    def update_scan_progress(self, current, total):
        """Update progress during scanning with detailed tracking"""
        progress = 0.2 + (0.8 * current / total) if total > 0 else 0.2
        self.update_progress(progress)
        
        def update_feed():
            timestamp = datetime.now().strftime("%H:%M:%S")
            progress_percent = int(progress * 100)
            self.live_feed.insert(tk.END, f"📊 [{timestamp}] Scan Progress: {current}/{total} URLs ({progress_percent}%)\n")
            self.live_feed.see(tk.END)
        self.root.after(0, update_feed)
    
    def display_results(self, results):
        """Display simple scan completion message"""
        vulnerable_results = [r for r in results if getattr(r, 'is_vulnerable', False)]
        scan_type_names = {
            'sqli': 'SQL Injection',
            'xss': 'Cross-Site Scripting (XSS)', 
            'crlf': 'CRLF Injection',
            'cmd': 'Command Injection'
        }
        
        self.results_text.delete("1.0", tk.END)
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        scan_type_display = scan_type_names.get(self.current_scan_type.get(), self.current_scan_type.get().upper())
        
        if vulnerable_results:
            status_icon = "🚨"
            status_text = "VULNERABILITIES FOUND"
            status_color = "#F44336"  # Red
            
            confidence_info = ""
            for result in vulnerable_results:
                additional_info = getattr(result, 'additional_info', {})
                if additional_info.get('confidence_score'):
                    confidence_info = f" (Confidence: {additional_info['confidence_score']})"
                    break
            
            recommendation = f"⚠️ Found {len(vulnerable_results)} vulnerability{'ies' if len(vulnerable_results) != 1 else 'y'}{confidence_info}! Export PDF report for detailed analysis."
        else:
            status_icon = "✅"
            status_text = "SECURE"
            status_color = "#4CAF50"  # Green
            recommendation = "✅ No vulnerabilities detected. Your application appears secure against this attack type."
        
        completion_message = f"""
        
    🛡️  SCAN COMPLETED SUCCESSFULLY
    
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    
    {status_icon}  STATUS: {status_text}
    
    📊 SCAN SUMMARY:
       • Target: {self.target_url.get()}
       • Type: {scan_type_display}
       • URLs Analyzed: {len(set(getattr(r, 'url', '') for r in results))}
       • Completed: {timestamp}
    
    📋 NEXT STEPS:
       {recommendation}
       
       📄 Click 'Export PDF' to generate detailed report
       🔄 Run additional scan types for comprehensive testing
    
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    
        """
        
        self.results_text.insert(tk.END, completion_message)
    
    def stop_scan(self):
        """Stop the current scan"""
        self.scanning = False
        if hasattr(self.sqli_scanner, 'stop'):
            self.sqli_scanner.stop()
        if hasattr(self.xss_scanner, 'stop'):
            self.xss_scanner.stop()
        if hasattr(self.crlf_scanner, 'stop'):
            self.crlf_scanner.stop()
        if hasattr(self.cmd_scanner, 'stop'):
            self.cmd_scanner.stop()
        
        self.update_status("⏹️ Scan stopped by user")
        self.scan_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        if not self.scan_results:
            self.export_button.configure(state="disabled")
    
    def export_results(self):
        """Export results to PDF"""
        if not self.scan_results:
            if MODERN_GUI_AVAILABLE:
                self.show_modern_error("No results to export")
            else:
                messagebox.showwarning("Warning", "No results to export")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")],
            title="Save Scan Report"
        )
        
        if file_path:
            try:
                results_data = []
                for result in self.scan_results:
                    result_dict = {
                        'url': getattr(result, 'url', ''),
                        'is_vulnerable': getattr(result, 'is_vulnerable', False),
                        'vulnerability_type': getattr(result, 'vulnerability_type', ''),
                        'risk_level': getattr(result, 'risk_level', ''),
                        'payload': getattr(result, 'payload', ''),
                        'error_message': getattr(result, 'error_message', ''),
                        'timestamp': getattr(result, 'timestamp', datetime.now()),
                        'additional_info': getattr(result, 'additional_info', {})
                    }
                    results_data.append(result_dict)
                
                report_data = self.report_generator.generate_pdf_report_data(
                    results_data,
                    self.current_scan_type.get(),
                    self.target_url.get(),
                    self.crawled_urls,
                    self.scan_duration
                )
                
                success = self.report_generator.generate_pdf_report(report_data, file_path)
                
                if success:
                    self.update_status(f"📄 Report exported to: {file_path}")
                    if MODERN_GUI_AVAILABLE:
                        self.show_modern_success(f"Report saved successfully!\\n{file_path}")
                    else:
                        messagebox.showinfo("Success", f"Report saved successfully!\\n{file_path}")
                else:
                    self.update_status("❌ Failed to export report")
                    
            except Exception as e:
                self.update_status(f"❌ Export failed: {str(e)}")
                if MODERN_GUI_AVAILABLE:
                    self.show_modern_error(f"Failed to export report: {str(e)}")
                else:
                    messagebox.showerror("Error", f"Failed to export report: {str(e)}")
    
    def clear_results(self):
        """Clear the results text area"""
        self.results_text.delete(1.0, tk.END)
        
        welcome_message = """
        
    🛡️  WEB APPLICATION SCANNER BETA
    
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    
    ✨ Ready for Advanced Security Testing
    
    📋 QUICK START:
       1. Select vulnerability scan type above (5 types available)
       2. Enter target URL to test  
       3. Enable crawling (recommended)
       4. Click 'Start Security Scan'
       5. Watch live vulnerability feed →
       6. Export PDF report when complete
    
    🎯 BETA FEATURES:
       • Real-time vulnerability detection feed
       • Advanced payload testing (in development)
       • Exploitation mode (coming soon)
       • Dark/Light mode toggle
       • Enhanced confidence scoring
    
    🚀 FUTURE SCOPE:
       • Advanced evasion techniques
       • Automated exploit generation
       • Machine learning payload optimization
       • API security testing
       • Mobile app security analysis
    
    Ready to scan... 🔍
    
        """
        
        self.results_text.insert(tk.END, welcome_message)
        
        if hasattr(self, 'status_indicator'):
            self.status_indicator.configure(text="● Ready", text_color="#2196F3")
        if hasattr(self, 'status_label'):
            self.status_label.configure(text="Ready to scan...")
        if hasattr(self, 'progress_label'):
            self.progress_label.configure(text="Ready to scan")
            
        self._results_displayed = False
    
    def show_modern_success(self, message):
        """Show modern success dialog"""
        success_window = ctk.CTkToplevel(self.root)
        success_window.title("Success")
        success_window.geometry("400x150")
        success_window.transient(self.root)
        success_window.grab_set()
        
        success_window.update_idletasks()
        x = (success_window.winfo_screenwidth() // 2) - (400 // 2)
        y = (success_window.winfo_screenheight() // 2) - (150 // 2)
        success_window.geometry(f"400x150+{x}+{y}")
        
        ctk.CTkLabel(success_window, text="✅ Success", font=ctk.CTkFont(size=16, weight="bold"), text_color="#4CAF50").pack(pady=20)
        ctk.CTkLabel(success_window, text=message).pack(pady=10)
        ctk.CTkButton(success_window, text="OK", command=success_window.destroy).pack(pady=10)
    
    def run(self):
        """Start the GUI application"""
        self.root.mainloop()


if __name__ == "__main__":
    print("🚀 Starting Web Application Scanner Beta...")
    
    if MODERN_GUI_AVAILABLE:
        print("✨ Using modern CustomTkinter interface")
        print("🆕 Beta Features: Live feed, Dark mode, Future scanners")
        app = ModernSecurityScannerGUI()
        app.run()
    else:
        print("❌ CustomTkinter not available!")
        print("💡 This application requires CustomTkinter for the modern interface.")
        print("📦 Please install it with one of these commands:")
        print("   • pip install customtkinter")
        print("   • python -m pip install customtkinter")
        print("   • Or use the virtual environment: /home/kali/Desktop/WebScannerProject/venv/bin/python main.py")
        sys.exit(1)
