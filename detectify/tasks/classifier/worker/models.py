from typing import Optional

import faust


class MalwareDetectionTask(faust.Record):
    task_id: str
    filepath: str
    sha256: Optional[str] = None
    report_path: Optional[str] = None
    model_score: Optional[float] = None
    model_label_id: Optional[int] = None
    model_label: Optional[str] = None
