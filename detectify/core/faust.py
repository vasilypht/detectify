from pathlib import Path

from faust import App
from redis.asyncio import Redis
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.asyncio import (
    create_async_engine,
    AsyncSession,
)

from detectify.helpers.config import load_config


class App(App):
    def __init__(self, config_name: str, *args, **kwargs):
        self.config = load_config(config_name)
        kwargs['broker'] = self.config.kafka.uri
        super().__init__(*args, **kwargs)
        
        self.cache_dir = Path(self.config.cache_dir)
        if not (self.cache_dir.exists() and self.cache_dir.is_dir()):
            raise ValueError(f'The {self.cache_dir} folder does not exist or is not a directory.')
        
        self.files_cache_dir = self.cache_dir / 'files'
        if not (self.files_cache_dir.exists() and self.files_cache_dir.is_dir()):
            raise ValueError(f'The {self.files_cache_dir} folder does not exist or is not a directory.')
        
        self.reports_cache_dir = self.cache_dir / 'reports'
        self.reports_cache_dir.mkdir(exist_ok=True)
        self.redis_client = Redis.from_url(url=self.config.redis.uri)
        
        self.database_engine = None
        self.database_async_session = None
        if self.config.database_uri:
            self.database_engine = create_async_engine(self.config.database_uri, echo=True)
            self.database_async_session = sessionmaker(
                self.database_engine, class_=AsyncSession, expire_on_commit=False
            )

    async def on_stop(self) -> None:
        await super().on_stop()
        await self._redis_client.close()
