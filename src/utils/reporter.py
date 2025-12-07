#!/usr/bin/env python3
"""
Reporter module for generating security scan reports.
Дипломный проект - Автоматизированный веб-сканер
"""

import json
import datetime
import os
from typing import List, Dict, Any


class Reporter:
    """Generates various types of security reports."""
    
    def __init__(self, output_dir: str = "security_reports"):
        self.output_dir = output_dir
    
    def generate_json_report(self, 
                           vulnerabilities: List[Dict[str, Any]], 
                           filename: str = "security_report.json") -> str:
        """Generate JSON format report."""
        report = {
            "scan_date": datetime.datetime.now().isoformat(),
            "total_vulnerabilities": len(vulnerabilities),
            "vulnerabilities": vulnerabilities
        }
        
        os.makedirs(self.output_dir, exist_ok=True)
        
        filepath = f"{self.output_dir}/{filename}"
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return filepath
    
    def generate_markdown_report(self, 
                                vulnerabilities: List[Dict[str, Any]], 
                                filename: str = "security_report.md") -> str:
        """Generate Markdown format report."""
        os.makedirs(self.output_dir, exist_ok=True)
        
        filepath = f"{self.output_dir}/{filename}"
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(f"# Security Scan Report\n\n")
            f.write(f"**Date:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"**Total Vulnerabilities Found:** {len(vulnerabilities)}\n\n")
            
            if vulnerabilities:
                f.write("## Vulnerabilities Details:\n\n")
                for i, vuln in enumerate(vulnerabilities, 1):
                    f.write(f"### {i}. {vuln.get('title', 'Vulnerability')}\n")
                    f.write(f"- **Type:** {vuln.get('type', 'Unknown')}\n")
                    f.write(f"- **Severity:** {vuln.get('severity', 'Medium')}\n")
                    f.write(f"- **Description:** {vuln.get('description', '')}\n")
                    f.write(f"- **Recommendation:** {vuln.get('recommendation', '')}\n\n")
            else:
                f.write("## ✅ No vulnerabilities found\n")
        
        return filepath
