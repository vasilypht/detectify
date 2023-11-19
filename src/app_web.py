import os
import json
import time
import functools
from uuid import uuid4
from datetime import timedelta

import gradio as gr
from redis import Redis
from fastapi import FastAPI
from celery.result import AsyncResult

from src import config
from src.celery import task_pipeline, app_celery
from src.constants import CeleryStatus


# By default, Gradio saves files in /temp. This folder is not
# very convenient to clean, so we reassign it to our own.
os.environ['GRADIO_TEMP_DIR'] = config.gradio.cache_dir


app = FastAPI()


def with_redis_connection(redis_uri: str):
    def wrapped(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            with Redis.from_url(redis_uri) as redis_store:
                yield from func(redis_store, *args, **kwargs)
                
        return wrapper
    return wrapped
        

@with_redis_connection(config.celery.backend_uri)
def button_compute_clicked(redis_store, file, *args, **kwargs):
    if file is None:
        return
    
    task_id = str(uuid4())
    task_redis_key = f'celery-task-meta-{task_id}'
    try:
        redis_store.setex(
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
        if task.status == CeleryStatus.QUEUED:
            yield 'QUEUED'
        elif task.status == CeleryStatus.PROGRESS:
            yield f'PROGRESS - {task.info.get("info")}'
        elif task.status == CeleryStatus.FAILURE:
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


def input_file_changed(data):
    if data:
        return gr.Button.update(interactive=True)
    else:
        return gr.Button.update(interactive=False)


with gr.Blocks(analytics_enabled=False) as demo:
    with gr.Row():
        with gr.Column():
            # Input file for classification.
            input_file = gr.File(
                file_count='single',
                label='File'
            )
    
            with gr.Row():
                # Button for clearing the input file widget and the results widget.
                # The button operation logic is described below.
                button_clear = gr.Button(
                    value='Clear'
                )
                
                # Button to start the processing process. Initially the button
                # is inactive because the file is missing.
                button_compute = gr.Button(
                    value='Compute',
                    interactive=False,
                )
        
        with gr.Column():
            # Widget for displaying the classification result.
            output_label = gr.Label()
    
    # Event for activating the file processing stratum button
    # if there is a loaded file, and deactivating the button
    # if the file is deleted.
    input_file.change(
        fn=lambda data: gr.Button.update(interactive=True) if data else gr.Button.update(interactive=False),
        inputs=input_file,
        outputs=button_compute,
    )
    
    button_clear.click(
        fn=lambda _: [None, None],
        inputs=None,
        outputs=[input_file, output_label]
    )
    button_compute.click(
        fn=button_compute_clicked,
        inputs=input_file,
        outputs=output_label,
    )


# Enabling the queue, as it is necessary for the generator to operate.
demo.queue()
gr.mount_gradio_app(app, demo, '/')
