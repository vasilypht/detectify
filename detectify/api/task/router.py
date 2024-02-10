import aiofiles
from fastapi.responses import JSONResponse
from fastapi import (
    APIRouter,
    UploadFile,
    Request,
    status,
)

from detectify.core.task import TaskStatus


router = APIRouter(prefix='/task')


@router.post('/create')
async def create_task(request: Request, file: UploadFile):
    """Method for creating a file classification task.

    Parameters
    ----------
    request : Request
        A request instance containing client data.
    file : UploadFile
        File for analysis.
    """
    # Saving the file to the cache folder.
    async with aiofiles.open(request.app.files_cache_dir / file.filename, 'wb') as out_file:
        while content := await file.read(1024):
            await out_file.write(content)

    try:
        task = await request.app.create_task(
            task_data={ 'file_path': str(request.app.files_cache_dir / file.filename) }
        )
    except Exception as e:
        return JSONResponse(
            content='Internal Server Error',
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    return JSONResponse(
        content={
            'task_id': task.id,
            'status': TaskStatus.QUEUED,
        },
        status_code=status.HTTP_200_OK,
    )


@router.get('/status/{task_id:str}')
async def task_status(request: Request, task_id: str):
    """Method for checking the status of a task.

    Parameters
    ----------
    request : Request
        A request instance containing client data.
    task_id : str
        ID tasks.
    """
    try:
        task = await request.app.recieve_result(task_id)
    except Exception as e:
        return JSONResponse(
            content='Internal Server Error',
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    if task is None:
        return JSONResponse(
            content={
                'task_id': task_id,
                'status': TaskStatus.NOT_FOUND,
            },
            status_code=status.HTTP_404_NOT_FOUND,
        )
        
    match task.status:
        case TaskStatus.QUEUED | TaskStatus.STARTED | TaskStatus.PROGRESS:
            return JSONResponse(
                content={
                    'task_id': task.id,
                    'status': task.status,
                    'meta': task.meta,
                },
                status_code=status.HTTP_202_ACCEPTED
            )
        case TaskStatus.FAILURE:
            return JSONResponse(
                content={
                    'task_id': task.id,
                    'status': task.status,
                    'meta': task.meta,
                },
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        case TaskStatus.SUCCESS:
            return JSONResponse(
                content={
                    'task_id': task.id,
                    'status': task.status,
                    'result': task.result,
                },
                status_code=status.HTTP_200_OK
            )
        case _:
            return JSONResponse(
                content={
                    'task_id': task.id,
                    'status': task.status,
                    'meta': 'Not Implemented',
                },
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
            )
