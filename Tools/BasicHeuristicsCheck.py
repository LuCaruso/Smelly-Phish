import tldextract
from urllib.parse import urlparse
import re

def extract_domain(url: str) -> str:
    if not url.lower().startswith(("http://", "https://")):
        url = "http://" + url
    parsed = urlparse(url)
    ext = tldextract.extract(parsed.netloc)
    return f"{ext.domain}.{ext.suffix}"

def detect_number_substitution(domain: str) -> bool:
    return any(ch.isdigit() for ch in domain) and any(ch.isalpha() for ch in domain)

def count_subdomains(url: str) -> int:
    if not url.lower().startswith(("http://", "https://")):
        url = "http://" + url
    parsed = urlparse(url)
    ext = tldextract.extract(parsed.netloc)
    return len(ext.subdomain.split('.')) if ext.subdomain else 0

def detect_special_chars(url: str) -> list:
    suspicious = set('@!#$%^&*;')
    return list({ch for ch in url if ch in suspicious})

def analyze_heuristics(url: str) -> dict:
    """
    Retorna um dict com:
      - domain: domínio raiz
      - num_sub: quantidade de subdomínios
      - number_sub: se há substituição numérica
      - specials: lista de caracteres especiais encontrados
      - suspicious: True se qualquer critério indicar risco
    """
    domain = extract_domain(url)
    num_sub = count_subdomains(url)
    number_sub = detect_number_substitution(domain)
    specials = detect_special_chars(url)
    suspicious = (num_sub > 2) or number_sub or bool(specials)
    return {
        "domain": domain,
        "num_sub": num_sub,
        "number_sub": number_sub,
        "specials": specials,
        "suspicious": suspicious
    }