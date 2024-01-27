from contextlib import asynccontextmanager

from detectify.core.fastapi import FastAPI
from detectify.api.task.router import router as task_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    await app.kafka_producer.start()
    yield
    await app.kafka_producer.stop()
    await app.redis_client.aclose()


app = FastAPI(lifespan=lifespan)

app.include_router(task_router, prefix='/api')
