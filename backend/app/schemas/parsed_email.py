from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.threat_detection import ThreatDetectionResult
from app.schemas.ml_detection import MLDetectionResult
from app.schemas.header_intelligence import HeaderIntelligenceResult
from app.schemas.infrastructure_intelligence import InfrastructureIntelligence
from app.schemas.probable_origin import ProbableOrigin
from app.schemas.campaign_correlation import CampaignCorrelation
from app.schemas.final_risk import FinalRisk


class ExtractedUrl(BaseModel):
    url: str
    hostname: str | None = None
    domain: str | None = None


class AttachmentMeta(BaseModel):
    filename: str
    mime_type: str
    size: int
    sha256: str


class MessageIdentities(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    subject: str | None = None
    from_: list[str] = Field(default_factory=list, alias="from", serialization_alias="from")
    to: list[str] = Field(default_factory=list)
    cc: list[str] = Field(default_factory=list)
    reply_to: list[str] = Field(default_factory=list)
    return_path: str | None = None
    date: str | None = None
    message_id: str | None = None


class HeaderBlock(BaseModel):
    received: list[str] = Field(default_factory=list)
    authentication_results: list[str] = Field(default_factory=list)
    received_spf: list[str] = Field(default_factory=list)
    dkim_signature: list[str] = Field(default_factory=list)
    dmarc: list[str] = Field(default_factory=list)
    raw: dict[str, list[str]] = Field(default_factory=dict)


class BodyBlock(BaseModel):
    plain_text: str = ""
    html: str = ""
    sanitized_text: str = ""
    sanitized_html: str = ""


class ParsedEmail(BaseModel):
    analysis_id: str | None = None
    filename: str | None = None
    analyzed_at: datetime | None = None
    message: MessageIdentities
    headers: HeaderBlock
    body: BodyBlock
    urls: list[ExtractedUrl] = Field(default_factory=list)
    attachments: list[AttachmentMeta] = Field(default_factory=list)
    threat_detection: ThreatDetectionResult | None = None
    ml_detection: MLDetectionResult | None = None
    header_intelligence: HeaderIntelligenceResult | None = None
    infrastructure_intelligence: InfrastructureIntelligence | None = None
    probable_origin: ProbableOrigin | None = None
    campaign_correlation: CampaignCorrelation | None = None
    final_risk: FinalRisk | None = None


class AnalyzeRawRequest(BaseModel):
    raw_eml: str
