import pathlib


PROJECT_DIR = pathlib.Path(__file__).parent.parent
MODEL_DIR = PROJECT_DIR / 'model'
DATA_DIR = PROJECT_DIR / 'data'
CACHE_DIR = PROJECT_DIR / 'cache'

REDIS_STORE_URI = 'redis://localhost:6379/0'
