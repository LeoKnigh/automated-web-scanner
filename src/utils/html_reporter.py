import json
from datetime import datetime

class Reporter:
    def __init__(self, scan_results):
        self.scan_results = scan_results
    
    def generate_console_report(self):
        """Генерация консольного отчета"""
        report_lines = []
        
        # Заголовок
        report_lines.append("=" * 60)
        report_lines.append("ОТЧЕТ СКАНИРОВАНИЯ БЕЗОПАСНОСТИ")
        report_lines.append(f"Цель: {self.scan_results.get('target', 'Не указана')}")
        report_lines.append(f"Время: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append("=" * 60)
        
        # Уязвимости
        vulnerabilities = self.scan_results.get('vulnerabilities', [])
        if vulnerabilities:
            report_lines.append("\n🚨 ОБНАРУЖЕННЫЕ УЯЗВИМОСТИ:")
            for i, vuln in enumerate(vulnerabilities, 1):
                if isinstance(vuln, dict):
                    report_lines.append(f"{i}. [{vuln.get('severity', 'UNKNOWN').upper()}] {vuln.get('type', 'UNKNOWN')}")
                    report_lines.append(f"   Описание: {vuln.get('description', 'Без описания')}")
                    if 'details' in vuln:
                        report_lines.append(f"   Детали: {vuln.get('details')[:100]}...")
        else:
            report_lines.append("\n✅ Уязвимости не обнаружены")
        
        # Предупреждения
        warnings = self.scan_results.get('warnings', [])
        if warnings:
            report_lines.append("\n⚠️  ПРЕДУПРЕЖДЕНИЯ:")
            for warning in warnings:
                report_lines.append(f"• {warning}")
        
        # Информация
        info_items = self.scan_results.get('info', [])
        if info_items:
            report_lines.append("\nℹ️  ИНФОРМАЦИЯ:")
            for info in info_items:
                report_lines.append(f"• {info}")
        
        # Итог
        report_lines.append("\n" + "=" * 60)
        report_lines.append(f"ИТОГО: Уязвимости: {len(vulnerabilities)}, Предупреждения: {len(warnings)}")
        report_lines.append("=" * 60)
        
        return "\n".join(report_lines)
    
    def generate_json_report(self, filename="scan_report.json"):
        """Генерация JSON отчета"""
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.scan_results, f, indent=2, ensure_ascii=False)
        return filename
