import json
from uuid import uuid4
from datetime import timedelta

import fastapi
from aiokafka import AIOKafkaProducer
from redis.asyncio import Redis

from .task import Task


class FastAPI(fastapi.FastAPI):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.kafka_producer = AIOKafkaProducer(bootstrap_servers='localhost:9094')
        self.redis_client = Redis.from_url(url='redis://localhost:6379/0', decode_responses=True)

    async def create_task(self, *, task_data: dict):
        task_id = str(uuid4())
        task = Task(task_id)

        async with self.redis_client.pipeline(transaction=True) as pipe:
            result = await (
                pipe.hset(task_id, mapping=task.to_dict(as_redis_hash_store=True))
                    .expire(task_id, time=timedelta(weeks=1))
                    .execute()
            )
            
        kafka_data = {
            'task_id': task_id,
            **task_data,
        }
        
        try:
            await self.kafka_producer.send_and_wait(
                topic='malware-detection.task.available',
                value=json.dumps(kafka_data).encode(),
            )
        except Exception as e:
            await self.redis_client.delete(task_id)
            raise Exception('Error') from e
    
        return task
    
    async def recieve_result(self, task_id: str):
        data = await self.redis_client.hgetall(task_id)
        if not data:
            return None
        
        data['result'] = json.loads(data.get('result', '{}'))
        return Task.from_dict(data)
    