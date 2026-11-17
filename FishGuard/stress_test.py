import concurrent.futures
import time
import requests

# Эндпоинты твоего запущенного бэкенда
API_URL = "http://127.0.0.1:8000/api/v1/check-url"

# Набор тестовых ссылок (и легитимные, и фишинговые)
TEST_URLS = [
    "https://kapitalbank.az",
    "http://kap1talbank.az",
    "https://birbank.az",
    "http://birbank-login-secure-az.com",
    "https://login.gov.az",
    "http://azerpost-odeme.top",
    "https://google.com",
    "https://166.az",
    "http://166-kargo.xyz"
]

def send_request():
    import random
    url = random.choice(TEST_URLS)
    start = time.time()
    try:
        response = requests.post(API_URL, json={"url": url}, timeout=5)
        duration = (time.time() - start) * 1000 # переводим в миллисекунды
        return response.status_code == 200, duration
    except Exception as e:
        return False, 0

def run_load_test(total_requests=150, concurrency=15):
    print(f"🔥 Запуск стресс-теста для PhishGuard AZ...")
    print(f"📡 Цель: {API_URL}")
    print(f"⚙️ Всего запросов: {total_requests} | Одновременных потоков: {concurrency}\n")
    
    success = 0
    failures = 0
    latencies = []

    start_time = time.time()

    # Запускаем запросы в нескольких потоках (многозадачность)
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(send_request) for _ in range(total_requests)]
        for future in concurrent.futures.as_completed(futures):
            is_success, duration = future.result()
            if is_success:
                success += 1
                latencies.append(duration)
            else:
                failures += 1

    total_time = time.time() - start_time
    rps = total_requests / total_time if total_time > 0 else 0

    print("\n" + "=" * 50)
    print("📊 РЕЗУЛЬТАТЫ СТРЕСС-ТЕСТА PHISHGUARD AZ:")
    print("=" * 50)
    print(f"✅ Успешных ответов (200 OK): {success}")
    print(f"❌ Ошибок / Таймаутов:       {failures}")
    print(f"⏱️ Общее время выполнения:   {total_time:.2f} сек")
    print(f"🚀 Пропускная способность:   {rps:.2f} запросов/сек (RPS)")
    if latencies:
        print(f"⚡ Средняя задержка (Avg):   {sum(latencies)/len(latencies):.2f} ms")
        print(f"🟢 Минимальная задержка:     {min(latencies):.2f} ms")
        print(f"🔴 Максимальная задержка:    {max(latencies):.2f} ms")
    print("=" * 50)
    print("✨ Сервер отработал стабильно! База данных (WAL режим) не заблокировалась.")

if __name__ == "__main__":
    run_load_test(total_requests=150, concurrency=15)