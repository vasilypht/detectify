import json
import time
import functools
from uuid import uuid4
from datetime import timedelta

import gradio as gr
from redis import Redis
from fastapi import FastAPI
from celery.result import AsyncResult

from src.celery import task_pipeline, app_celery
from src.config import BACKEND_CONN_URI


app = FastAPI()


def with_redis_connection(redis_uri: str):
    def wrapped(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            with Redis.from_url(redis_uri) as redis_store:
                yield from func(redis_store, *args, **kwargs)
                
        return wrapper
    return wrapped
        

@with_redis_connection(BACKEND_CONN_URI)
def button_compute_clicked(redis_store, file, *args, **kwargs):
    task_id = str(uuid4())
    task_redis_key = f'celery-task-meta-{task_id}'
    try:
        redis_store.setex(
            name=task_redis_key,
            time=timedelta(weeks=1),
            value=json.dumps(
                {
                    'task_id': task_id,
                    'status': 'QUEUED'
                }
            )
        )
    except Exception:
        return 'Error'
        
    try:
        task_args = ({'file_path': file.name},)
        task = task_pipeline.apply_async(
            args=task_args,
            task_id=task_id,
        )
    except Exception:
        redis_store.delete(task_redis_key)
        return 'Error'
    
    while True:
        task = AsyncResult(task.id, app=app_celery)
        if task.status == 'QUEUED':
            yield 'QUEUED'
        elif task.status == 'PROGRESS':
            yield f'PROGRESS - {task.info.get("info")}'
        elif task.status == 'FAILURE':
            return 'FAILURE - Internal Server Error'
        else:
            break
        time.sleep(1)

    label_mapping = {
        'benign': 'malware',
        'malware': 'benign',
    }

    result = task.result
    yield {
        result['label']: result['score'],
        label_mapping[result['label']]: 1-result['score']
    }


with gr.Blocks(analytics_enabled=False) as demo:
    with gr.Row():
        with gr.Column():
            input_file = gr.File(
                file_count='single',
                label='File'
            )
    
            with gr.Row():
                button_clear = gr.Button(
                    value='Clear'
                )
                button_compute = gr.Button(
                    value='Compute',
                )
        
        with gr.Column():
            output_label = gr.Label()
    
    button_clear.click(
        fn=lambda: [None, None],
        inputs=None,
        outputs=[input_file, output_label]
    )
    button_compute.click(
        fn=button_compute_clicked,
        inputs=input_file,
        outputs=output_label,
    )


demo.queue()
gr.mount_gradio_app(app, demo, '/')
