import hashlib

from redis.asyncio import Redis

from ..app import app
from tasks.config import (
    DATA_DIR,
    REDIS_STORE_URI,
)
from .topics import (
    topic_sha256_calculation,
    topic_available_task,
    topic_completed_task,
    topic_classification,
    topic_receiving_report,
)


redis_store = Redis.from_url(REDIS_STORE_URI)


@app.agent(topic_available_task)
async def available_task_handler(tasks):
    async for task in tasks:
        await topic_sha256_calculation.send(value=task)


@app.agent(topic_sha256_calculation)
async def sha256_calculation_handler(tasks):
    async for task in tasks:
        hash_instance = hashlib.sha256()
        buffer = bytearray(1024 * 128)
        buffer_view = memoryview(buffer)
        with open(task.filepath, 'rb', buffering=0) as file:
            while n := file.readinto(buffer_view):
                hash_instance.update(buffer_view[:n])

        task.sha256 = hash_instance.hexdigest()
        await topic_receiving_report.send(value=task)


@app.agent(topic_receiving_report)
async def receiving_report_handler(tasks):
    async for task in tasks:
        value = await redis_store.get(task.sha256)

        # TODO Add an option to ignore search
        if value is not None:
            raise NotImplementedError()

        # TODO Receive a report via the Virus Total API.
        reports_dir = DATA_DIR / 'pe-machine-learning-dataset' / 'reports'
        report_path = reports_dir / f'{task.sha256}.json'
        task.report_path = str(report_path)

        await topic_classification.send(value=task)


@app.agent(topic_completed_task)
async def completed_task_handler(tasks):
    async for task in tasks:
        pass
