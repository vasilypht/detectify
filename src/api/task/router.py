import aiofiles
from fastapi import (
    APIRouter,
    status,
    UploadFile
)
from fastapi.responses import JSONResponse
from celery.result import AsyncResult
from celery import chain

from src.celery import (
    task_calculate_sha256,
    task_search_hash_in_db,
    task_get_report,
    task_classification,
)
from src.config import CACHE_DIR


router = APIRouter(prefix='/task')


@router.post('/create')
async def create_task(file: UploadFile):
    async with aiofiles.open(CACHE_DIR / file.filename, 'wb') as out_file:
        while content := await file.read(1024):
            await out_file.write(content)

    task = chain(
        task_calculate_sha256.s({'file_path': str(CACHE_DIR / file.filename)}),
        task_search_hash_in_db.s(),
        task_get_report.s(),
        task_classification.s(),
    ).apply_async()

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
            },
            status_code=status.HTTP_202_ACCEPTED,
        )
        
    if not task.successful():
        return JSONResponse(
            content={
                'task_id': task.id,
                'status': task.status,
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
