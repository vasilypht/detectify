from detectify.core.faust import App


autodiscover = [
    'detectify.tasks.classifier',
]


app = App(
    id='faust-malware-detection',
    broker='kafka://localhost:9094',
    web_enabled=False,
    autodiscover=autodiscover,
)
