import faust
from redis.asyncio import Redis


class FaustApp(faust.App):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._redis_client = Redis.from_url(url='redis://localhost:6379/0')

    @property
    def redis_client(self) -> Redis:
        return self._redis_client

    async def on_stop(self) -> None:
        await super().on_stop()

        await self._redis_client.close()
