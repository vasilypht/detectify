from detectify.core.faustapp import FaustApp


autodiscover = [
    'detectify.tasks.core',
]


app = FaustApp(
    id='faust-malware-detection',
    broker='kafka://localhost:9094',
    web_enabled=False,
    autodiscover=autodiscover,
)
