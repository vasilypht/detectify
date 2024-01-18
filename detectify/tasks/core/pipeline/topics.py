from ..app import app
from .models import MalwareDetectionTask


topic_available_task = app.topic('malware-detection.task.available', value_type=MalwareDetectionTask)
topic_sha256_calculation = app.topic('malware-detection.task.sha256-calculation', value_type=MalwareDetectionTask)
topic_receiving_report = app.topic('malware-detection.task.receiving-report', value_type=MalwareDetectionTask)
topic_classification = app.topic('malware-detection.task.classification', value_type=MalwareDetectionTask)
topic_completed_task = app.topic('malware-detection.task.completed', value_type=MalwareDetectionTask)
