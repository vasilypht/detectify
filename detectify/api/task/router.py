import json
from uuid import uuid4
from datetime import timedelta

import aiofiles
from fastapi import (
    APIRouter,
    UploadFile,
    Request,
    status,
)
from fastapi.responses import JSONResponse

from detectify.core.task import Task
from detectify.config import CACHE_DIR


router = APIRouter(prefix='/task')


@router.post('/create')
async def create_task(request: Request, file: UploadFile):
    async with aiofiles.open(CACHE_DIR / file.filename, 'wb') as out_file:
        while content := await file.read(1024):
            await out_file.write(content)

    task_id = str(uuid4())

    try:
        result = await Task.create(task_id, app=request.app)
    except Exception as e:
        return JSONResponse(
            content='Internal Server Error',
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    kafka_data = {
        'task_id': task_id,
        'filepath': str(CACHE_DIR / file.filename),
    }

    try:
        await request.app.kafka_producer.send_and_wait(
            topic='malware-detection.task.available',
            value=json.dumps(kafka_data).encode(),
        )
    except:
        await request.app.redis_client.delete(task_id)
        return JSONResponse(
            content='Internal Server Error',
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    return JSONResponse(
        content={
            'task_id': task_id,
            'status': 'QUEUED',
        },
        status_code=status.HTTP_200_OK,
    )


@router.get('/status/{task_id:str}')
async def task_status(request: Request, task_id: str):
    try:
        task = await Task.recieve(task_id, app=request.app)
    except Exception as e:
        return JSONResponse(
            content='Internal Server Error',
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    if task is None:
        return JSONResponse(
            content={
                'task_id': task_id,
                'status': 'NOT FOUND',
            },
            status_code=status.HTTP_404_NOT_FOUND,
        )
        
    match task.status:
        case 'QUEUED' | 'STARTED' | 'PROGRESS':
            return JSONResponse(
                content={
                    'task_id': task.id,
                    'status': task.status,
                    'meta': task.meta,
                },
                status_code=status.HTTP_202_ACCEPTED
            )

        case 'FAILURE':
            return JSONResponse(
                content={
                    'task_id': task.id,
                    'status': task.status,
                    'meta': task.meta,
                },
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            
        case 'COMPLETED':
            return JSONResponse(
                content={
                    'task_id': task.id,
                    'status': task.status,
                    'result': task.result,
                },
                status_code=status.HTTP_200_OK
            )
