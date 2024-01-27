from detectify.tasks.classifier import app
from .models import MalwareDetectionTask


topic_classification = app.topic('malware-detection.task.classification', value_type=MalwareDetectionTask)
topic_completed_task = app.topic('malware-detection.task.completed', value_type=MalwareDetectionTask)
