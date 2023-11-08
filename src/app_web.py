import time

import gradio as gr
from fastapi import FastAPI
from celery.result import AsyncResult

from src.celery import task_pipeline, app_celery


def button_compute_clicked(file):
    task = task_pipeline.delay({'file_path': file})
    while True:
        task = AsyncResult(task.id, app=app_celery)
        if task.status not in ('QUEUED', 'PROGRESS'):
            break
        yield f'{task.status} - {task.info.get("info")}'
        time.sleep(1)

    print(task)
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


app = FastAPI()
gr.mount_gradio_app(app, demo, '/')
    