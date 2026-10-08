from pydantic import BaseModel


class ReportRequest(BaseModel):
    analysis_id: str
