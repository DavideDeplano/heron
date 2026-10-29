"""Read and parse relevant parts of the file."""
from email.utils import parseaddr

def sender_domain(header_value):
    """Return the email address domain or None if `@` is missing."""
    _, address = parseaddr(header_value)
    if "@" not in address:
        return None
    return address.rsplit("@", 1)[1].lower()
