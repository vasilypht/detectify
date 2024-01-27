import json
from typing import Optional
from datetime import timedelta

from .fastapi import FastAPI


class Task:
    def __init__(
        self,
        *,
        id_: str,
        status: str,
        meta: str,
        result: dict,
    ) -> None:
        if isinstance(id_, str):
            self._id = id_
        else:
            raise ValueError('The task id must be a string.')
        
        if isinstance(status, str):
            self._status = status
        else:
            raise ValueError('The status must be a string.')
        
        if isinstance(meta, str):
            self._meta = meta
        else:
            raise ValueError('The meta must be a string.')
        
        if isinstance(result, dict):
            self._result = result
        else:
            raise ValueError('The result must be a string.')

    @classmethod
    async def create(
        cls,
        id_: str,
        *,
        app: FastAPI,
        expire: timedelta = timedelta(weeks=1),
        status: Optional[str] = None,
        meta: Optional[str] = None,
        result: Optional[str] = None,
    ):
        result = {} if result is None else result
        meta = '' if meta is None else meta
        status = 'QUEUED' if status is None else status
        
        task = cls(
            id_=id_,
            status=status,
            meta=meta,
            result=result,
        )
        
        async with app.redis_client.pipeline(transaction=True) as pipe:
            result = await (
                pipe.hset(id_, mapping=task.to_dict(as_redis_hash_store=True))
                    .expire(id_, time=expire)
                    .execute()
            )
        
        return result
        
        
    @classmethod
    async def recieve(
        cls,
        id_: str,
        *,
        app: FastAPI,
    ):
        data = await app.redis_client.hgetall(id_)
        if not data:
            return None
        data['result'] = json.loads(data.get('result', '{}'))
        return cls(
            id_=id_,
            status=data.get('status'),
            meta=data.get('meta'),
            result=data['result'],
        )
        
    def to_dict(self, *, as_redis_hash_store: bool = False):
        data = {
            'id': self.id,
            'status': self.status,
            'meta': self.meta,
            'result': self.result,
        }
        if as_redis_hash_store:
            data['result'] = json.dumps(data['result'])
        return data
            
    @property
    def id(self):
        return self._id
    
    @property
    def status(self):
        return self._status
    
    @property
    def meta(self):
        return self._meta
    
    @property
    def result(self):
        return self._result
    