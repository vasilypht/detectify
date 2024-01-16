import pathlib


TASKS_DIR = pathlib.Path(__file__).parent
PROJECT_DIR = TASKS_DIR.parent
MODEL_DIR = PROJECT_DIR / 'model'
DATA_DIR = PROJECT_DIR / 'data'

REDIS_STORE_URI = 'redis://localhost:6379/0'
