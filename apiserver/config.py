import pathlib


SERVICE_DIR = pathlib.Path(__file__).parent
PROJECT_DIR = SERVICE_DIR.parent
CACHE_DIR = PROJECT_DIR / 'cache'
