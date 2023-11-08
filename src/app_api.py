from fastapi import FastAPI

from .api.task import router as task_router


app = FastAPI()

app.include_router(task_router.router, prefix='/api')

