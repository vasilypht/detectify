import faust


autodiscover = [
    'detectify.tasks.classifier',
]


app = faust.App(
    id='faust-malware-detection',
    broker='kafka://localhost:9094',
    web_enabled=False,
    autodiscover=autodiscover,
)
