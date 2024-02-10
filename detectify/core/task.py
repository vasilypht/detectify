import json
from enum import Enum
from typing import Optional


class TaskStatus(str, Enum):
    NOT_FOUND = "NOT FOUND"
    QUEUED = "QUEUED"
    STARTED = "STARTED"
    PROGRESS = "PROGRESS"
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    
    def __str__(self) -> str:
        return self.value
    

class Task:
    def __init__(
        self,
        id_: str,
        *,
        status: Optional[str | TaskStatus] = None,
        meta: Optional[str] = None,
        result: Optional[dict] = None,
    ) -> None:
        """Initializing a class to work with a task.

        Parameters
        ----------
        id_ : str
            Task ID.
        status : Optional[str  |  TaskStatus], optional
            Task status, by default None
        meta : Optional[str], optional
            Additional status information, by default None
        result : Optional[dict], optional
            Task result data, by default None
        """
        self._id = id_
        match status:
            case str():
                status = TaskStatus(status)
            case None:
                status = TaskStatus.QUEUED
            case TaskStatus():
                pass
        self._status = status
        if meta is None:
            meta = ''
        self._meta = meta
        if result is None:
            result = {}
        self._result = result
        
    def to_dict(self, *, as_redis_hash_store: bool = False) -> dict:
        """A method for representing a task in the form of a dictionary.

        Parameters
        ----------
        as_redis_hash_store : bool, optional
            Serialize fields for Radish hash map, by default False

        Returns
        -------
        dict
            Representation of a task in the form of a dictionary.
        """
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
