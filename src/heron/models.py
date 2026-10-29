from dataclasses import dataclass

@dataclass(frozen=True)
class ParsedEmail:
    """Dataclass that holds the parsed email attributes"""
    email_id: str
    sender: str
    from_domain: str | None
    reply_to_domain: str | None
    auth_result: str
    text: str
    links: tuple[str]

