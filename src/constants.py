from enum import Enum


class CeleryStatus(str, Enum):
    QUEUED = 'QUEUED'
    PROGRESS = 'PROGRESS'
    FAILURE = 'FAILURE'