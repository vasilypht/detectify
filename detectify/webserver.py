import os
import time

import requests
import gradio as gr
from fastapi import FastAPI

from detectify.core.task import TaskStatus
from detectify.helpers.config import load_config


config = load_config('gradio.yaml')
# By default, Gradio saves files in /temp. This folder is not
# very convenient to clean, so we reassign it to our own.
os.environ['GRADIO_TEMP_DIR'] = config.cache_dir


app = FastAPI()


def button_compute_clicked(file):
    if file is None:
        return

    files = {
        'file': open(file.name, 'rb'),
    }
    response = requests.post('http://127.0.0.1:9900/api/task/create', files=files)
    body_json = response.json()
    while True:
        response = requests.get(f'http://127.0.0.1:9900/api/task/status/{body_json["task_id"]}')
        body_json = response.json()
        match body_json['status']:
            case TaskStatus.QUEUED | TaskStatus.PROGRESS | TaskStatus.STARTED as status:
                meta = body_json.get("meta", "...")
                if not meta:
                    meta = '...'
                yield f'{status} - {meta}'
            case TaskStatus.FAILURE:
                return 'FAILURE - Internal Server Error'
            case _:
                break
        time.sleep(1)

    label_mapping = {
        'benign': 'malware',
        'malware': 'benign',
    }
    
    result = body_json["result"]
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
