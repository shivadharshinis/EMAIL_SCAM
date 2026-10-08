from dataclasses import dataclass, field


@dataclass
class AnalysisRecord:
    sender_domains: set[str] = field(default_factory=set)
    reply_to_domains: set[str] = field(default_factory=set)
    return_path_domains: set[str] = field(default_factory=set)
    public_ips: set[str] = field(default_factory=set)
    url_domains: set[str] = field(default_factory=set)
    subject: str = ""
    rule_score: int = 0
    ml_probability: float | None = None

