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

from apiserver.config import CACHE_DIR


router = APIRouter(prefix='/task')


@router.post('/create')
async def create_task(request: Request, file: UploadFile):
    async with aiofiles.open(CACHE_DIR / file.filename, 'wb') as out_file:
        while content := await file.read(1024):
            await out_file.write(content)

    task_id = str(uuid4())

    try:
        redis_value = {
            'task_id': task_id,
            'status': 'QUEUED',
            'result': None,
        }
        await request.app.redis_client.setex(
            name=task_id,
            time=timedelta(weeks=1),
            value=json.dumps(redis_value)
        )
    except:
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
        data_str = await request.app.redis_client.get(task_id)
    except:
        return JSONResponse(
            content='Internal Server Error',
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    if not data_str:
        return JSONResponse(
            content={
                'task_id': task_id,
                'status': 'NOT FOUND',
            },
            status_code=status.HTTP_404_NOT_FOUND,
        )

    task_data = json.loads(data_str)

    if task_data['status'] in ['QUEUED', 'STARTED', 'PROGRESS']:
        return JSONResponse(
            content={
                'task_id': task_data['task_id'],
                'status': task_data['status'],
            },
            status_code=status.HTTP_200_OK
        )

    if task_data['status'] == 'FAILURE':
        return JSONResponse(
            content={
                'task_id': task_data['task_id'],
                'status': task_data['status'],
                'message': task_data.get('message'),
            },
            status_code=status.HTTP_200_OK
        )

    return JSONResponse(
        content={
            'task_id': task_data['task_id'],
            'status': task_data['status'],
            'result': task_data['result'],
        },
        status_code=status.HTTP_200_OK
    )



