import os
from pathlib import Path
from dataclasses import dataclass


SOURCE_DIR = Path(__file__).parent
PROJECT_DIR = SOURCE_DIR.parent
DATA_DIR = PROJECT_DIR / 'data'
MODEL_DIR = PROJECT_DIR / 'model'
CACHE_DIR = PROJECT_DIR / 'cache'
CACHE_DIR.mkdir(exist_ok=True, parents=True)


@dataclass
class RedisSchema:
    host: str = 'localhost'
    port: int = 6379
    celery_db_index: int = 0
    store_db_index: int = 1


@dataclass
class RabbitMQSchema:
    host: str = 'localhost'
    username: str = 'guest'
    password: str = 'guest'
    port: int = 5672
    

@dataclass
class CelerySchema:
    redis: RedisSchema = RedisSchema()
    rabbitmq: RabbitMQSchema = RabbitMQSchema()
    
    backend_uri: str = f'redis://{redis.host}:{redis.port}/{redis.celery_db_index}'
    store_uri: str = f'redis://{redis.host}:{redis.port}/{redis.store_db_index}'
    
    broker_uri: str = f'amqp://{rabbitmq.username}:{rabbitmq.password}@{rabbitmq.host}:{rabbitmq.port}'


@dataclass
class ModelSchema:
    path: str = str(MODEL_DIR)
    device: str = 'cpu'
    batch_size: int = 1


@dataclass
class GradioSchema:
    cache_dir: str = str(CACHE_DIR)


@dataclass
class ConfigSchema:
    celery: CelerySchema = CelerySchema()
    gradio: GradioSchema = GradioSchema()
    model: ModelSchema = ModelSchema()


config = ConfigSchema()
