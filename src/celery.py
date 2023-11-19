import hashlib

import redis
from celery import Celery, Task
from celery.exceptions import Ignore

from src.malware_detection_model import MalwareDetectionPipeline
from src.extractor import VirusTotalFeatureExtractor
from src.parsers import extract_texts
from src import config
from src.config_loader import (
    DATA_DIR,
)


app_celery = Celery(
    broker=config.celery.broker_uri,
    backend=config.celery.backend_uri
)
redis_store = redis.from_url(config.celery.store_uri)


class ModelTask(Task):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.model = None
        
    def __call__(self, *args, **kwargs):
        if self.model is None:
            self.model = MalwareDetectionPipeline(model_path=config.model.path)
        
        return self.run(*args, **kwargs)


@app_celery.task(bind=True, ignore_result=True)
def task_pipeline(self, data: dict):
    """
    Task for launching the first task of the pipeline.
    
    Parameters
    ----------
    data : dict
        A dictionary with the path to the file.
        
        The dictionary has the following structure:
        {
            'file_path': 'path/to/file',
        }
        
    Notes
    -----
    This task creates the first task of the pipeline with the same
    task ID. The result of the current task is ignored.
    """
    task_pipeline_calculate_sha256.apply_async(
        args=(data,),
        task_id=self.request.id,
    )
    raise Ignore()


@app_celery.task(bind=True, ignore_result=True)
def task_pipeline_calculate_sha256(self, data: dict):
    """
    Pipeline task for calculating the hash (sha256) of a file.
    
    Parameters
    ----------
    data : dict
        A dictionary with the path to the file.
        
        The dictionary has the following structure:
        {
            'file_path': 'path/to/file',
        }
    """
    self.update_state(
        state='PROGRESS',
        meta={
            'task': 'task_calculate_sha256',
            'info': 'Hash calculation...'
        }
    )
    
    _hash = hashlib.sha256()
    buffer = bytearray(1024 * 128)
    buffer_view = memoryview(buffer)
    with open(data['file_path'], 'rb', buffering=0) as file:
        while n := file.readinto(buffer_view):
            _hash.update(buffer_view[:n])
    
    data['sha256'] = _hash.hexdigest()
    
    task_pipeline_getting_report.apply_async(
        args=(data,),
        task_id=self.request.id,
    )
    raise Ignore()
    

@app_celery.task(bind=True, ignore_result=True)
def task_pipeline_getting_report(self, data: dict):
    """
    Pipeline task to receive a report.

    First, the presence of an entry in the database is checked using
    the hash; if there is an entry, the result is returned. If there
    is no record, then the report will begin to be received using
    the VirusTotal API.
    
    Parameters
    ----------
    data : dict        
        The dictionary has the following structure:
        {
            'file_path': 'path/to/file',
            'sha256': '<some_hash>',
        }
    """
    self.update_state(
        state='PROGRESS',
        meta={
            'task': 'task_search_hash_in_db',
            'info': 'Checking in the database...',
        }
    )
    value = redis_store.get(data['sha256'])
    
    # TODO Add an option to ignore search
    if value is not None:
        return value    
    
    self.update_state(
        state='PROGRESS',
        meta={
            'task': 'task_get_report',
            'info': 'Receiving a report...',
        }
    )
    
    # TODO Receive a report via the Virus Total API.
    reports_dir = DATA_DIR / 'pe-machine-learning-dataset' / 'reports'
    report_path = reports_dir / f'{data["sha256"]}.json'
    data['report'] = str(report_path)
    
    task_pipeline_classification.apply_async(
        args=(data,),
        task_id=self.request.id,
    )
    raise Ignore()


@app_celery.task(bind=True, base=ModelTask)
def task_pipeline_classification(self, data: dict):
    """
    Pipeline task for file classification.

    From the received report, features are extracted - texts, from
    which a large corpus is formed. The resulting body will be
    divided into overlapping pieces and then fed into the model.
    Next, the result will be selected with priority for maliciousness.
    
    Parameters
    ----------
    data : dict        
        The dictionary has the following structure:
        {
            'file_path': 'path/to/file',
            'sha256': '<some_hash>',
            'report': 'path/to/file'
        }
    """
    self.update_state(
        state='PROGRESS',
        meta={
            'task': 'task_classification',
            'info': 'Classification...',
        }
    )
    extractor = VirusTotalFeatureExtractor.from_json(data['report'])
    corpus = '\n'.join(extract_texts(extractor))
    
    # TODO Make the split not in the model class, iteratively call
    # the model with the split data.
    result = self.model(
        file_path=data['file_path'],
        text=corpus
    )
    
    data['score'] = result['score']
    # TODO Make a proxy method to get the name of the tags.
    data['label'] = self.model.model.config.id2label.get(result['label_id'])
    return data
