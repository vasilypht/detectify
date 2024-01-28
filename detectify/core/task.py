import json
from typing import Optional


class Task:
    def __init__(
        self,
        id_: str,
        *,
        status: Optional[str] = None,
        meta: Optional[str] = None,
        result: Optional[dict] = None,
    ) -> None:
        self._id = id_
        
        if status is None:
            status = 'QUEUED'
        
        self._status = status
        
        if meta is None:
            meta = ''
            
        self._meta = meta
        
        if result is None:
            result = {}
            
        self._result = result
        
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
    
    @classmethod
    def from_dict(cls, data: dict):
        return cls(
            id_=data.get('id'),
            status=data.get('status'),
            meta=data.get('meta'),
            result=data.get('result'),
        )
            
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
    