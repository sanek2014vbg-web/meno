import asyncio
import random
import string
import time
from dataclasses import dataclass
from typing import List, Optional

import httpx
from loguru import logger

# ================= CONFIGURATION =================
BASE_URL = "http://localhost:8000"
USER_COUNT = 50            # Количество мастер-аккаунтов
MSG_PER_USER_MIN = 4       # Мин. сообщений на пользователя
MSG_PER_USER_MAX = 10      # Макс. сообщений на пользователя
CONCURRENCY_LIMIT = 10     # Лимит одновременных запросов (Semaphore)
TIMEOUT = 10.0             # Таймаут запроса в секундах
# =================================================

@dataclass
class UserSession:
    phone: str
    token: str
    user_id: int

class InfrastructureSeeder:
    def __init__(self):
        self.client = httpx.AsyncClient(
            base_url=BASE_URL, 
            timeout=TIMEOUT, 
            limits=httpx.Limits(max_connections=100)
        )
        self.semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)
        self.sessions: List[UserSession] = []
        self.stats = {
            "success": 0,
            "errors": 0,
            "start_time": 0.0
        }

    async def safe_request(self, method: str, endpoint: str, **kwargs):
        """Обертка для запросов с Graceful Fallback и замером времени."""
        async with self.semaphore:
            start = time.perf_counter()
            try:
                response = await self.client.request(method, endpoint, **kwargs)
                duration = int((time.perf_counter() - start) * 1000)
                
                if response.status_code in (200, 201):
                    self.stats["success"] += 1
                    return response, duration
                else:
                    logger.warning(f"Request {method} {endpoint} failed [{response.status_code}] in {duration}ms")
                    self.stats["errors"] += 1
                    return None, duration
            except Exception as e:
                duration = int((time.perf_counter() - start) * 1000)
                logger.error(f"Exception during {method} {endpoint}: {e}")
                self.stats["errors"] += 1
                return None, duration

    async def sanity_check(self):
        """1. ПРОВЕРКА СВЯЗИ И ЗДОРОВЬЯ."""
        logger.info("🚀 Starting Sanity Check...")
        endpoints = ["/", "/healthz"]
        for ep in endpoints:
            res, dur = await self.safe_request("GET", ep)
            if res:
                logger.success(f"Healthcheck {ep} passed in {dur}ms")
            else:
                logger.critical(f"Healthcheck {ep} failed! Infrastructure is not ready.")
                return False
        return True

    def _generate_fake_phone(self):
        return f"7999{random.randint(1000000, 9999999)}"

    async def seed_users(self):
        """2. ГЕНЕРАЦИЯ И НАПОЛНЕНИЕ ПОЛЬЗОВАТЕЛЕЙ."""
        logger.info(f"👥 Seeding {USER_COUNT} users...")
        
        tasks = []
        for i in range(USER_COUNT):
            phone = self._generate_fake_phone()
            name = f"User_{i}_{''.join(random.choices(string.ascii_letters, k=4))}"
            tasks.append(self._create_single_user(phone, name))
        
        await asyncio.gather(*tasks)
        logger.info(f"Successfully created {len(self.sessions)} users.")

    async def _create_single_user(self, phone: str, name: str):
        # Шаг 1: Запрос кода (проверяем пропускную способность /api/register)
        res1, _ = await self.safe_request("POST", "/api/register", json={"phone": phone})
        if not res1: return

        # Шаг 2: Верификация (тестовый код 123456)
        payload = {
            "phone": phone,
            "code": "123456", 
            "password": "Password123!",
            "display_name": name
        }
        res2, _ = await self.safe_request("POST", "/api/verify", json=payload)
        
        if res2:
            data = res2.json()
            token = data["tokens"]["access_token"]
            user_id = data["user"]["id"]
            self.sessions.append(UserSession(phone, token, user_id))

    async def seed_interactions(self):
        """2. Создание графа связей (Чаты и Сообщения)."""
        if not self.sessions:
            logger.error("No users available for interactions!")
            return

        logger.info("💬 Generating chats and messages graph...")
        
        # Групповые чаты
        for i in range(5):
            group_members = random.sample(self.sessions, random.randint(3, 10))
            creator = group_members[0]
            headers = {"Authorization": f"Bearer {creator.token}"}
            payload = {
                "type": "group",
                "title": f"StressGroup_{i}",
                "user_ids": [u.user_id for u in group_members[1:]]
            }
            res, _ = await self.safe_request("POST", "/api/chats", json=payload, headers=headers)
            if res:
                chat_id = res.json()["id"]
                await self._fill_chat_with_messages(chat_id, group_members)

        # Личные чаты
        for _ in range(20):
            u1, u2 = random.sample(self.sessions, 2)
            headers = {"Authorization": f"Bearer {u1.token}"}
            payload = {"type": "personal", "user_ids": [u2.user_id]}
            res, _ = await self.safe_request("POST", "/api/chats", json=payload, headers=headers)
            if res:
                chat_id = res.json()["id"]
                await self._fill_chat_with_messages(chat_id, [u1, u2])

    async def _fill_chat_with_messages(self, chat_id: int, members: List[UserSession]):
        num_msgs = random.randint(MSG_PER_USER_MIN, MSG_PER_USER_MAX) * len(members)
        for _ in range(num_msgs):
            sender = random.choice(members)
            headers = {"Authorization": f"Bearer {sender.token}"}
            payload = {
                "type": "text",
                "content": f"Benchmark msg {random.randint(1, 1000000)}: {' '.join(random.choices(string.ascii_lowercase, k=20))}",
                "e2e": random.choice([True, False])
            }
            await self.safe_request("POST", f"/api/chats/{chat_id}/messages", json=payload, headers=headers)

    async def warmup_cache(self):
        """3. ПРОГРЕВ СЛОЯ КЭШИРОВАНИЯ (Redis)."""
        logger.info("🔥 Warming up Redis cache...")
        tasks = []
        for session in self.sessions:
            headers = {"Authorization": f"Bearer {session.token}"}
            tasks.append(self.safe_request("GET", "/api/me", headers=headers))
            tasks.append(self.safe_request("GET", "/api/chats", headers=headers))
        
        await asyncio.gather(*tasks)
        logger.success("Cache warmup completed.")

    async def run(self):
        self.stats["start_time"] = time.perf_counter()
        if not await self.sanity_check():
            logger.critical("Sanity check failed. Aborting.")
            return

        await self.seed_users()
        await self.seed_interactions()
        await self.warmup_cache()
        
        total_duration = time.perf_counter() - self.stats["start_time"]
        logger.info("="*40)
        logger.info("SEEDING REPORT")
        logger.info(f"Total Duration: {total_duration:.2f}s")
        logger.info(f"Successful Requests: {self.stats['success']}")
        logger.info(f"Failed Requests: {self.stats['errors']}")
        logger.info(f"Error Rate: {(self.stats['errors'] / (self.stats['success'] + self.stats['errors']) * 100):.2f}%")
        logger.info("="*40)

async def main():
    seeder = InfrastructureSeeder()
    try:
        await seeder.run()
    finally:
        await seeder.client.aclose()

if __name__ == "__main__":
    logger.add("seeding.log", rotation="10 MB")
    asyncio.run(main())
