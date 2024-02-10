from detectify.vit_longformer import ViTLongformerPipeline
from detectify.extractors import VirusTotalFeatureExtractor

from detectify.tasks.classifier import app
from .topics import (
    topic_completed_tasks,
    topic_classifications,
)


model = ViTLongformerPipeline(model_path=app.config.model_path)


@app.agent(topic_classifications)
async def classifications_handler(tasks):
    """File classification stream."""
    async for task in tasks:
        extractor = VirusTotalFeatureExtractor.from_json(task.report_path)
        corpus = '\n'.join(extractor.extract_all())
        result = model(file_path=task.file_path, corpus=corpus)
        task.model_score = result['score']
        task.model_label_id = result['label_id']
        task.model_label = model.model.config.id2label.get(result['label_id'])
        await topic_completed_tasks.send(value=task)
