from detectify.core.faust import App


config_name = 'core.yaml'
app_id='faust-malware-detection'
autodiscover = [
    'detectify.tasks.core',
]

app = App(
    config_name=config_name,
    id=app_id,
    web_enabled=False,
    autodiscover=autodiscover,
)
