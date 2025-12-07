"""
ТЕСТОВЫЙ ФАЙЛ С УЯЗВИМОСТЯМИ ДЛЯ ДИПЛОМНОГО ПРОЕКТА
Назначение: демонстрация работы Bandit и OpenGrep
"""

import hashlib
import pickle
import subprocess
import requests

# ========== УЯЗВИМОСТИ ДЛЯ BANDIT ==========

# 1. Слабая хэш-функция (BAN: слабый криптоалгоритм)
def weak_password_hash(password):
    """Уязвимость: использование MD5"""
    return hashlib.md5(password.encode()).hexdigest()  # BAN: B303

# 2. Использование pickle (BAN: десериализация ненадежных данных)
def load_data(data):
    """Уязвимость: десериализация"""
    return pickle.loads(data)  # BAN: B301

# 3. Выполнение shell команд (BAN: инъекция команд)
def run_command(cmd):
    """Уязвимость: выполнение shell команд"""
    return subprocess.call(cmd, shell=True)  # BAN: B602

# 4. Hardcoded пароль (BAN: хардкод секретов)
DATABASE_PASSWORD = "super_secret_123"  # BAN: B105

# ========== УЯЗВИМОСТИ ДЛЯ OPENGREP ==========

# 5. SQL инъекция (наш custom rule)
def sql_query(user_input):
    """Уязвимость: конкатенация SQL"""
    query = "SELECT * FROM users WHERE id = " + user_input  # SQL_INJECTION
    return query

# 6. Hardcoded API ключ (наш custom rule)
API_KEY = "sk_live_1234567890abcdef"  # HARCODED_SECRET

# 7. SSRF потенциальная (наш custom rule)
def fetch_url(user_url):
    """Потенциальная SSRF уязвимость"""
    response = requests.get(user_url)  # SSRF_POTENTIAL
    return response.text

# ========== БЕЗОПАСНЫЙ КОД ==========

def secure_password_hash(password):
    """Безопасная хэш-функция"""
    return hashlib.sha256(password.encode()).hexdigest()

def safe_sql_query(user_id):
    """Безопасный SQL запрос"""
    # Используем параметризованные запросы
    query = "SELECT * FROM users WHERE id = %s"
    return query, (user_id,)

if __name__ == "__main__":
    print("Тестовый файл с уязвимостями для дипломного проекта")
    print("Цель: продемонстрировать работу статических анализаторов")
    
    # Тестовый вызов уязвимых функций
    test_pass = "test123"
    print(f"MD5 хэш: {weak_password_hash(test_pass)}")
    print(f"Secure хэш: {secure_password_hash(test_pass)}")
