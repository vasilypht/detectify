from contextlib import asynccontextmanager

from apiserver.app import APIServer
from apiserver.api.task.router import router as task_router


@asynccontextmanager
async def lifespan(app: APIServer):
    await app.kafka_producer.start()
    yield
    await app.kafka_producer.stop()
    await app.redis_client.aclose()


app = APIServer(lifespan=lifespan)

app.include_router(task_router, prefix='/api')

