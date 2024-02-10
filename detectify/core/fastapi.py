import json
from uuid import uuid4
from pathlib import Path
from datetime import timedelta

from fastapi import FastAPI
from aiokafka import AIOKafkaProducer
from redis.asyncio import Redis

from detectify.core.task import Task, TaskStatus
from detectify.helpers.config import load_config


class FastAPI(FastAPI):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.config = load_config('apiserver.yaml')
        
        # Checking the shared cache folder.
        self.cache_dir = Path(self.config.cache_dir)
        if not (self.cache_dir.exists() and self.cache_dir.is_dir()):
            raise ValueError(f'The {self.cache_dir} folder does not exist or is not a directory.')
        
        self.files_cache_dir = self.cache_dir / 'files'
        self.files_cache_dir.mkdir(exist_ok=True)

        self.kafka_producer = AIOKafkaProducer(bootstrap_servers=self.config.kafka.uri)
        self.redis_client = Redis.from_url(url=self.config.redis.uri, decode_responses=True)

    async def create_task(self, *, task_data: dict) -> Task:
        """Method for creating a task.

        Parameters
        ----------
        task_data : dict
            Data for creating a task.

        Returns
        -------
        Task
            Created task.
        """
        task_id = str(uuid4())
        task = Task(task_id)
        # Creating a record in Redis that the task has been queued.
        async with self.redis_client.pipeline(transaction=True) as pipe:
            result = await (
                pipe.hset(task_id, mapping=task.to_dict(as_redis_hash_store=True))
                    .expire(task_id, time=timedelta(weeks=1))
                    .execute()
            )
        # Sending task data to Kafka.
        kafka_data = {'task_id': task_id, **task_data}
        try:
            await self.kafka_producer.send_and_wait(
                topic=self.config.kafka.topics.available_tasks,
                value=json.dumps(kafka_data).encode(),
            )
        except Exception as e:
            # Deleting an entry if there is an error.
            await self.redis_client.delete(task_id)
            raise Exception('Error') from e
        return task
    
    async def recieve_result(self, task_id: str) -> Task:
        """Method for getting the current state of a task.

        Parameters
        ----------
        task_id : str
            ID of the task for which you want to request the current state.

        Returns
        -------
        Task
            A task with the current state of the task.
        """
        data = await self.redis_client.hgetall(task_id)
        if not data:
            return None
        data['result'] = json.loads(data.get('result', '{}'))
        return Task(
            id_=data.get('id', ''),
            status=data.get('status', TaskStatus.NOT_FOUND),
            result=data.get('result', {}),
            meta=data.get('meta', ''),
        )
    