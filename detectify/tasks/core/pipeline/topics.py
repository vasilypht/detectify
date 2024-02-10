from detectify.tasks.core import app
from .models import DetectifyTaskRecord


topic_available_tasks = app.topic(app.config.kafka.topics.available_tasks, value_type=DetectifyTaskRecord)
topic_sha256_calculations = app.topic(app.config.kafka.topics.sha256_calculations, value_type=DetectifyTaskRecord)
topic_receiving_reports = app.topic(app.config.kafka.topics.receiving_reports, value_type=DetectifyTaskRecord)
topic_classifications = app.topic(app.config.kafka.topics.classifications, value_type=DetectifyTaskRecord)
topic_completed_tasks = app.topic(app.config.kafka.topics.completed_tasks, value_type=DetectifyTaskRecord)
