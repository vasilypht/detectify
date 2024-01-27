import fastapi
from aiokafka import AIOKafkaProducer
from redis.asyncio import Redis


class FastAPI(fastapi.FastAPI):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.kafka_producer = AIOKafkaProducer(bootstrap_servers='localhost:9094')
        self.redis_client = Redis.from_url(url='redis://localhost:6379/0', decode_responses=True)
