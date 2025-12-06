# Automated Web Vulnerability Scanner

## Дипломный проект 
Студент: Захаров Леонид Александрович
Группа: КТСО-04-20
Специальность: Информационная безопасность телекоммуникационных систем

## Описание
Разработан инструмент для автоматического сканирования веб-приложений на наличие уязвимостей. 
Включает статический (SAST) и динамический (DAST) анализ.

## Функциональность
- Проверка безопасности HTTP-заголовков
- Обнаружение SQL-инъекций, XSS
- Анализ SSL/TLS настроек
- Интеграция с CI/CD (GitHub Actions)

## Технологии
- Python 3.9
- Bandit, Semgrep (SAST)
- OWASP ZAP (DAST)
- Docker, Docker Compose
- GitHub Actions

## Установка
```bash
git clone https://github.com/LeoKnight/automated-web-scanner.git
cd automated-web-scanner
pip install -r requirements.txt
