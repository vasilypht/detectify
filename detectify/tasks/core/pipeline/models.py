from typing import Optional

from faust import Record


class DetectifyTaskRecord(Record):
    task_id: str
    file_path: str
    sha256: Optional[str] = None
    report_path: Optional[str] = None
    model_score: Optional[float] = None
    model_label_id: Optional[int] = None
    model_label: Optional[str] = None
