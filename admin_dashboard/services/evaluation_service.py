import json
from pathlib import Path

class EvaluationService:
    def __init__(self,path):self.path=Path(path)
    def read(self):
        if not self.path.is_file():return dict(available=False,message='No evaluation collected. Run python -m lab_tests.evaluation locally.')
        if self.path.stat().st_size>2*1024*1024:raise ValueError('Evaluation artifact exceeds size limit')
        try:
            report=json.loads(self.path.read_text(encoding='utf-8'))
            if not isinstance(report,dict) or not all(k in report for k in ('run_id','created_at','effectiveness','performance')):raise ValueError()
        except (ValueError,OSError):return dict(available=False,message='Evaluation artifact is invalid or unavailable.')
        return dict(available=True,report=report)
