import json
import hashlib

import redis
from celery import Celery, Task

from src.malware_detection_model import MalwareDetectionPipeline
from src.extractor import VirusTotalFeatureExtractor
from src.parsers import extract_texts
from .config import (
    BROKER_CONN_URI,
    BACKEND_CONN_URI,
    STORE_CONN_URI,
    DATA_DIR,
    MODEL_DIR,
)


app_celery = Celery(broker=BROKER_CONN_URI, backend=BACKEND_CONN_URI)
redis_store = redis.from_url(STORE_CONN_URI)


class ModelTask(Task):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.model = None
        
    def __call__(self, *args, **kwargs):
        if self.model is None:
            self.model = MalwareDetectionPipeline(model_path=MODEL_DIR)
        
        return self.run(*args, **kwargs)


@app_celery.task()
def task_calculate_sha256(data: dict):
    _hash = hashlib.sha256()
    buffer = bytearray(1024 * 128)
    buffer_view = memoryview(buffer)
    with open(data['file_path'], 'rb', buffering=0) as file:
        while n := file.readinto(buffer_view):
            _hash.update(buffer_view[:n])
    
    data['sha256'] = _hash.hexdigest()
    return data


@app_celery.task(bind=True)
def task_search_hash_in_db(self, data: dict):
    value = redis_store.get(data['sha256'])
    if value is not None:
        self.request.callbacks = None
        return value
    
    return data


@app_celery.task()
def task_get_report(data: dict):
    # TODO Add VT API
    
    reports_dir = DATA_DIR / 'pe-machine-learning-dataset' / 'reports'
    report_path = reports_dir / f'{data["sha256"]}.json'
    data['report'] = str(report_path)
    return data


@app_celery.task(bind=True, base=ModelTask)
def task_classification(self, data: dict):
    extractor = VirusTotalFeatureExtractor.from_json(data['report'])
    corpus = '\n'.join(extract_texts(extractor))
    
    result = self.model(
        file_path=data['file_path'],
        text=corpus
    )
    
    data['score'] = result['score']
    data['label'] = self.model.model.config.id2label.get(result['label_id'])
    return data
