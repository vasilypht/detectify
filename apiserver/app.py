from contextlib import asynccontextmanager

from fastapi import FastAPI
from aiokafka import AIOKafkaProducer
from redis.asyncio import Redis

from apiserver.api.task.router import router as task_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    await app.kafka_producer.start()
    yield
    await app.kafka_producer.stop()
    await app.redis_client.aclose()


app = FastAPI(lifespan=lifespan)

app.kafka_producer = AIOKafkaProducer(bootstrap_servers='localhost:9094')
app.redis_client = Redis.from_url(url='redis://localhost:6379/0')

app.include_router(task_router, prefix='/api')
