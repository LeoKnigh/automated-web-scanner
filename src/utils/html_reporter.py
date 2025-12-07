"""
Модуль для генерации HTML отчетов
"""

import json
from datetime import datetime

class HTMLReporter:
    def __init__(self, scan_results):
        self.scan_results = scan_results
    
    def _escape_html(self, text):
        """Экранирование HTML символов"""
        if not text:
            return ""
        return (str(text)
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&#39;'))
    
    def _severity_to_color(self, severity):
        """Цвет для уровня серьезности"""
        colors = {
            'critical': '#dc3545',  # Красный
            'high': '#fd7e14',      # Оранжевый
            'medium': '#ffc107',    # Желтый
            'low': '#28a745',       # Зеленый
            'info': '#17a2b8',      # Голубой
        }
        return colors.get(severity.lower(), '#6c757d')  # Серый по умолчанию
    
    def generate_report(self, filename="scan_report.html"):
        """Генерация HTML отчета"""
        
        target = self.scan_results.get('target', 'Не указана')
        timestamp = self.scan_results.get('timestamp', datetime.now().isoformat())
        
        # Статистика
        vulnerabilities = self.scan_results.get('vulnerabilities', [])
        warnings = self.scan_results.get('warnings', [])
        info_items = self.scan_results.get('info', [])
        
        # Группировка уязвимостей по типу
        vuln_by_type = {}
        for vuln in vulnerabilities:
            if isinstance(vuln, dict):
                vuln_type = vuln.get('type', 'UNKNOWN')
                vuln_by_type[vuln_type] = vuln_by_type.get(vuln_type, 0) + 1
        
        html = f'''<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Отчет сканирования уязвимостей</title>
    <style>
        :root {{
            --primary-color: #2c3e50;
            --secondary-color: #3498db;
            --success-color: #27ae60;
            --warning-color: #f39c12;
            --danger-color: #e74c3c;
            --info-color: #17a2b8;
            --light-bg: #f8f9fa;
            --dark-bg: #343a40;
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        .report-card {{
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            overflow: hidden;
            margin: 40px auto;
        }}
        
        .report-header {{
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .report-header h1 {{
            font-size: 2.5rem;
            margin-bottom: 10px;
            font-weight: 300;
        }}
        
        .report-header .subtitle {{
            font-size: 1.2rem;
            opacity: 0.9;
            margin-bottom: 20px;
        }}
        
        .scan-info {{
            display: flex;
            justify-content: space-around;
            flex-wrap: wrap;
            background: var(--light-bg);
            padding: 20px;
            border-bottom: 2px solid #eee;
        }}
        
        .info-item {{
            text-align: center;
            padding: 15px;
            min-width: 200px;
        }}
        
        .info-item .value {{
            font-size: 1.8rem;
            font-weight: bold;
            color: var(--primary-color);
        }}
        
        .info-item .label {{
            font-size: 0.9rem;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            padding: 30px;
        }}
        
        .stat-card {{
            background: white;
            border-radius: 10px;
            padding: 25px;
            text-align: center;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
            transition: transform 0.3s ease;
            border-top: 4px solid;
        }}
        
        .stat-card:hover {{
            transform: translateY(-5px);
        }}
        
        .stat-card.critical {{ border-top-color: var(--danger-color); }}
        .stat-card.high {{ border-top-color: var(--warning-color); }}
        .stat-card.medium {{ border-top-color: #ffc107; }}
        .stat-card.low {{ border-top-color: var(--success-color); }}
        
        .stat-card .number {{
            font-size: 3rem;
            font-weight: bold;
            margin-bottom: 10px;
        }}
        
        .stat-card.critical .number {{ color: var(--danger-color); }}
        .stat-card.high .number {{ color: var(--warning-color); }}
        .stat-card.medium .number {{ color: #ffc107; }}
        .stat-card.low .number {{ color: var(--success-color); }}
        
        .content-section {{
            padding: 30px;
        }}
        
        .section-title {{
            color: var(--primary-color);
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid var(--light-bg);
            font-size: 1.5rem;
        }}
        
        .vulnerability-list {{
            margin-top: 20px;
        }}
        
        .vulnerability-item {{
            background: white;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 15px;
            border-left: 5px solid;
            box-shadow: 0 3px 10px rgba(0, 0, 0, 0.08);
            transition: all 0.3s ease;
        }}
        
        .vulnerability-item:hover {{
            box-shadow: 0 5px 20px rgba(0, 0, 0, 0.15);
            transform: translateX(5px);
        }}
        
        .vulnerability-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        
        .severity-badge {{
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: bold;
            color: white;
            text-transform: uppercase;
        }}
        
        .vulnerability-details {{
            background: var(--light-bg);
            padding: 15px;
            border-radius: 8px;
            margin-top: 10px;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            overflow-x: auto;
        }}
        
        .type-tag {{
            display: inline-block;
            background: var(--info-color);
            color: white;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 0.8rem;
            margin-right: 10px;
        }}
        
        .footer {{
            background: var(--dark-bg);
            color: white;
            text-align: center;
            padding: 30px;
            margin-top: 40px;
        }}
        
        @media (max-width: 768px) {{
            .stats-grid {{
                grid-template-columns: 1fr;
            }}
            
            .scan-info {{
                flex-direction: column;
                align-items: center;
            }}
            
            .report-header h1 {{
                font-size: 2rem;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="report-card">
            <div class="report-header">
                <h1>🔍 Отчет сканирования уязвимостей</h1>
                <p class="subtitle">Автоматизированный сканер веб-приложений | Дипломный проект 2024</p>
            </div>
            
            <div class="scan-info">
                <div class="info-item">
                    <div class="value">{target}</div>
                    <div class="label">Цель сканирования</div>
                </div>
                <div class="info-item">
                    <div class="value">{datetime.fromisoformat(timestamp.replace('Z', '+00:00')).strftime('%d.%m.%Y %H:%M')}</div>
                    <div class="label">Дата и время</div>
                </div>
            </div>
            
            <div class="stats-grid">
                <div class="stat-card critical">
                    <div class="number">{len([v for v in vulnerabilities if isinstance(v, dict) and v.get('severity') == 'critical'])}</div>
                    <div class="label">Критические уязвимости</div>
                </div>
                <div class="stat-card high">
                    <div class="number">{len([v for v in vulnerabilities if isinstance(v, dict) and v.get('severity') == 'high'])}</div>
                    <div class="label">Высокие уязвимости</div>
                </div>
                <div class="stat-card medium">
                    <div class="number">{len([v for v in vulnerabilities if isinstance(v, dict) and v.get('severity') == 'medium'])}</div>
                    <div class="label">Средние уязвимости</div>
                </div>
                <div class="stat-card low">
                    <div class="number">{len(vulnerabilities)}</div>
                    <div class="label">Всего уязвимостей</div>
                </div>
            </div>
'''
        
        # Секция уязвимостей
        if vulnerabilities:
            html += '''
            <div class="content-section">
                <h2 class="section-title">🚨 Обнаруженные уязвимости</h2>
                <div class="vulnerability-list">
'''
            
            for i, vuln in enumerate(vulnerabilities, 1):
                if isinstance(vuln, dict):
                    severity = vuln.get('severity', 'medium')
                    severity_color = self._severity_to_color(severity)
                    
                    html += f'''
                    <div class="vulnerability-item" style="border-left-color: {severity_color};">
                        <div class="vulnerability-header">
                            <div>
                                <span class="type-tag">{vuln.get('type', 'UNKNOWN')}</span>
                                <strong>#{i}: {self._escape_html(vuln.get('description', 'Без описания'))}</strong>
                            </div>
                            <span class="severity-badge" style="background: {severity_color};">{severity.upper()}</span>
                        </div>
'''
                    
                    if 'details' in vuln:
                        html += f'''
                        <div class="vulnerability-details">
                            {self._escape_html(vuln.get('details'))}
                        </div>
'''
                    
                    if 'url' in vuln:
                        html += f'''
                        <div style="margin-top: 10px; font-size: 0.9rem;">
                            <strong>URL:</strong> {self._escape_html(vuln.get('url'))}
                        </div>
'''
                    
                    html += '''
                    </div>
'''
            
            html += '''
                </div>
            </div>
'''
        
        # Секция предупреждений
        if warnings:
            html += '''
            <div class="content-section">
                <h2 class="section-title">⚠️ Предупреждения</h2>
                <div class="vulnerability-list">
'''
            
            for warning in warnings:
                html += f'''
                    <div class="vulnerability-item" style="border-left-color: var(--warning-color);">
                        <div style="color: var(--warning-color);">
                            ⚠️ {self._escape_html(warning)}
                        </div>
                    </div>
'''
            
            html += '''
                </div>
            </div>
'''
        
        # Секция информации
        if info_items:
            html += '''
            <div class="content-section">
                <h2 class="section-title">ℹ️ Информация</h2>
                <div class="vulnerability-list">
'''
            
            for info in info_items:
                html += f'''
                    <div class="vulnerability-item" style="border-left-color: var(--info-color);">
                        <div style="color: var(--info-color);">
                            ℹ️ {self._escape_html(info)}
                        </div>
                    </div>
'''
            
            html += '''
                </div>
            </div>
'''
        
        # Футер
        html += f'''
            <div class="footer">
                <p>📄 Отчет сгенерирован автоматизированным сканером уязвимостей</p>
                <p>🎓 Дипломный проект 2024 | Информационная безопасность</p>
                <p>⏱️ Дата генерации: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}</p>
            </div>
        </div>
    </div>
    
    <script>
        // Простая анимация при загрузке
        document.addEventListener('DOMContentLoaded', function() {{
            const items = document.querySelectorAll('.vulnerability-item');
            items.forEach((item, index) => {{
                item.style.opacity = '0';
                item.style.transform = 'translateY(20px)';
                
                setTimeout(() => {{
                    item.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
                    item.style.opacity = '1';
                    item.style.transform = 'translateY(0)';
                }}, index * 100);
            }});
        }});
    </script>
</body>
</html>
'''
        
        # Сохраняем файл
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return filename
