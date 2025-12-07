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

    def generate_console_report(self, scan_results):
        """Generate console output for scan results."""
        print("\n" + "="*80)
        print("SECURITY SCAN REPORT")
        print("="*80)
        print(f"Target: {scan_results.get('target', 'Unknown')}")
        print(f"Scan date: {scan_results.get('timestamp', 'Unknown')}")
        
        vulns = scan_results.get('vulnerabilities', [])
        warnings = scan_results.get('warnings', [])
        info = scan_results.get('info', [])
        
        print(f"\nVulnerabilities found: {len(vulns)}")
        if vulns:
            for i, vuln in enumerate(vulns, 1):
                print(f"  {i}. {vuln.get('title', 'Unknown')} "
                      f"(Severity: {vuln.get('severity', 'Medium')})")
        
        print(f"\nWarnings: {len(warnings)}")
        if warnings:
            for i, warning in enumerate(warnings, 1):
                print(f"  {i}. {warning.get('title', 'Unknown')}")
        
        print(f"\nInfo messages: {len(info)}")
        
        print("\n" + "="*80)
        print("END OF REPORT")
        print("="*80)
        
        return scan_results
        
        return filepath
