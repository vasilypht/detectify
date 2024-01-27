from detectify.resnet_longformer import MalwareDetectionPipeline
from detectify.extractors import VirusTotalFeatureExtractor

from detectify.tasks.classifier import app
from .topics import (
    topic_classification,
    topic_completed_task,
)
from detectify.config import (
    MODEL_DIR,
)


model = MalwareDetectionPipeline(model_path=MODEL_DIR)


@app.agent(topic_classification)
async def classification_handler(tasks):
    async for task in tasks:

        extractor = VirusTotalFeatureExtractor.from_json(task.report_path)
        corpus = '\n'.join(extractor.extract_all())

        result = model(
            file_path=task.filepath,
            text=corpus
        )

        task.model_score = result['score']
        task.model_label_id = result['label_id']
        # TODO Make a proxy method to get the name of the tags.
        task.model_label = model.model.config.id2label.get(result['label_id'])

        await topic_completed_task.send(value=task)
