from detectify.core.faust import App


config_name = 'classifier.yaml'
app_id = 'faust-malware-detection'
autodiscover = [
    'detectify.tasks.classifier',
]

app = App(
    config_name=config_name,
    id=app_id,
    web_enabled=False,
    autodiscover=autodiscover,
)
