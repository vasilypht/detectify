import aiofiles
from fastapi import (
    APIRouter,
    UploadFile,
    Request,
    status,
)
from fastapi.responses import JSONResponse

from detectify.config import CACHE_DIR


router = APIRouter(prefix='/task')


@router.post('/create')
async def create_task(request: Request, file: UploadFile):
    async with aiofiles.open(CACHE_DIR / file.filename, 'wb') as out_file:
        while content := await file.read(1024):
            await out_file.write(content)

    try:
        task = await request.app.create_task(
            task_data={ 'filepath': str(CACHE_DIR / file.filename) }
        )
    except Exception as e:
        return JSONResponse(
            content='Internal Server Error',
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    return JSONResponse(
        content={
            'task_id': task.id,
            'status': 'QUEUED',
        },
        status_code=status.HTTP_200_OK,
    )


@router.get('/status/{task_id:str}')
async def task_status(request: Request, task_id: str):
    try:
        task = await request.app.recieve_result(task_id)
    except Exception as e:
        print(e)
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
