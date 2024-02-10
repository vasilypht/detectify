from detectify.tasks.classifier import app
from .models import DetectifyTaskRecord


topic_classifications = app.topic(app.config.kafka.topics.classifications, value_type=DetectifyTaskRecord)
topic_completed_tasks = app.topic(app.config.kafka.topics.completed_tasks, value_type=DetectifyTaskRecord)
