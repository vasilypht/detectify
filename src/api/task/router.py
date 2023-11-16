import json
from uuid import uuid4
from datetime import timedelta

import aiofiles
import redis.asyncio as aioredis
from fastapi import (
    APIRouter,
    status,
    UploadFile
)
from fastapi.responses import JSONResponse
from celery.result import AsyncResult

from src import config
from src.celery import task_pipeline
from src.config_loader import CACHE_DIR
from src.constants import CeleryStatus


router = APIRouter(prefix='/task')
redis_backend = aioredis.from_url(config.celery.backend_uri)


@router.post('/create')
async def create_task(file: UploadFile):    
    async with aiofiles.open(CACHE_DIR / file.filename, 'wb') as out_file:
        while content := await file.read(1024):
            await out_file.write(content)
            
    task_id = str(uuid4())
    task_redis_key = f'celery-task-meta-{task_id}'
    try:
        await redis_backend.setex(
            name=task_redis_key,
            time=timedelta(weeks=1),
            value=json.dumps(
                {
                    'task_id': task_id,
                    'status': CeleryStatus.QUEUED,
                }
            )
        )
    except Exception:
        return JSONResponse(
            content='Internal Server Error',
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
        
    try:
        task_args = ({'file_path': str(CACHE_DIR / file.filename)},)
        task = task_pipeline.apply_async(
            args=task_args,
            task_id=task_id,
        )
    except Exception:
        await redis_backend.delete(task_redis_key)
        return JSONResponse(
            content='Internal Server Error',
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

    return JSONResponse(
        content={
            'task_id': task.id,
            'status': task.status,
        },
        status_code=status.HTTP_201_CREATED,
    )


@router.get('/status/{task_id:str}')
async def task_status(task_id: str):
    task = AsyncResult(task_id)
    if not task.ready():
        return JSONResponse(
            content={
                'task_id': task.id,
                'status': task.status,
                'info': task.info,
            },
            status_code=status.HTTP_202_ACCEPTED,
        )
        
    if not task.successful():
        return JSONResponse(
            content={
                'task_id': task.id,
                'status': task.status,
                'info': task.info,
            },
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
        
    return JSONResponse(
        content={
            'task_id': task.id,
            'status': task.status,
            'result': task.result,
        },
        status_code=status.HTTP_200_OK,
    )
