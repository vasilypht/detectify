from mwdetection.resnet_longformer_model import MalwareDetectionPipeline
from mwdetection.extractor import VirusTotalFeatureExtractor
from mwdetection.parsers import extract_texts

from ..app import app
from .topics import (
    topic_classification,
    topic_completed_task,
)
from tasks.config import (
    MODEL_DIR,
)


model = MalwareDetectionPipeline(model_path=MODEL_DIR)


@app.agent(topic_classification)
async def classification_handler(tasks):
    async for task in tasks:

        extractor = VirusTotalFeatureExtractor.from_json(task.report_path)
        corpus = '\n'.join(extract_texts(extractor))

        # TODO Make the split not in the model class, iteratively call
        # the model with the split data.
        result = model(
            file_path=task.filepath,
            text=corpus
        )

        task.model_score = result['score']
        task.model_label_id = result['label_id']
        # TODO Make a proxy method to get the name of the tags.
        task.model_label = model.model.config.id2label.get(result['label_id'])

        await topic_completed_task.send(value=task)
