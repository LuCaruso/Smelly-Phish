import socket
import ssl
import requests
import re
import whois
from datetime import datetime
from urllib.parse import urlparse
from difflib import SequenceMatcher
from io import BytesIO

# Lista de provedores de DNS dinâmico comuns
DYNAMIC_DNS_PROVIDERS = ["no-ip.org", "dyndns.org", "duckdns.org"]
# Lista de marcas conhecidas para checar similaridade (expandida)
KNOWN_BRANDS = [
    "google.com", "gmail.com", "facebook.com", "youtube.com", "twitter.com",
    "instagram.com", "linkedin.com", "wikipedia.org", "amazon.com",
    "paypal.com", "microsoft.com", "live.com", "outlook.com", "yahoo.com",
    "apple.com", "netflix.com", "spotify.com", "adobe.com",
    "github.com", "dropbox.com", "slack.com", "shopify.com",
    "salesforce.com", "wordpress.com", "pinterest.com", "reddit.com",
    "tumblr.com", "quora.com", "stackexchange.com", "stackoverflow.com",
    "azure.microsoft.com", "cloudflare.com",
    # Financeiras internacionais
    "chase.com", "bankofamerica.com", "wellsfargo.com", "hsbc.com",
    "citibank.com", "barclays.co.uk",
    # Principais marcas brasileiras
    "google.com.br", "mercadolivre.com.br", "mercadopago.com.br", "uol.com.br",
    "globo.com", "terra.com.br", "ig.com.br", "olx.com.br",
    "bancodobrasil.com.br", "bb.com.br", "itau.com.br", "bradesco.com.br",
    "caixa.gov.br", "nubank.com.br", "c6bank.com.br", "bancointer.com.br",
    "banrisul.com.br", "santander.com.br", "xp.com.br", "pagseguro.uol.com.br",
    "ebay.com.br", "magazineluiza.com.br", "americanas.com.br", "submarino.com.br",
    "netshoes.com.br", "vivo.com.br", "claro.com.br", "oi.com.br", "tim.com.br",
    "receita.fazenda.gov.br", "gov.br", "sebrae.com.br",
]


def get_domain_age_days(domain: str) -> int | None:
    """Retorna a idade do domínio em dias via WHOIS ou None se não for possível."""
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if isinstance(creation, datetime):
            return (datetime.utcnow() - creation).days
    except Exception:
        pass
    return None


def detect_dynamic_dns(domain: str) -> bool:
    """Verifica se o domínio usa DNS dinâmico conhecido."""
    return any(provider in domain for provider in DYNAMIC_DNS_PROVIDERS)


def analyze_ssl_info(domain: str) -> dict:
    """Retorna informações detalhadas do certificado SSL do domínio."""
    info = {
        "issuer": None,
        "expires": None,
        "match": False,
        "expired": False,
        "days_left": None
    }
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()

            # Emissor
            issuer = dict(x[0] for x in cert.get('issuer', ())).get('commonName')
            info["issuer"] = issuer

            # Data de expiração e cálculo de dias restantes
            not_after = cert.get('notAfter')
            expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            info["expires"] = expires
            info["expired"] = expires < datetime.utcnow()
            info["days_left"] = (expires - datetime.utcnow()).days

            # Verifica correspondência de domínio
            san = cert.get('subjectAltName', ())
            cert_domains = [entry[1].lower() for entry in san if entry[0] == 'DNS']
            info["match"] = domain.lower() in cert_domains

    except Exception:
        pass

    return info


def detect_redirects(url: str) -> bool:
    """Detecta redirecionamentos suspeitos na URL."""
    try:
        resp = requests.get(url, timeout=5, allow_redirects=True)
        if resp.history:
            orig = urlparse(url).netloc.lower()
            final = urlparse(resp.url).netloc.lower()
            return orig != final
    except Exception:
        pass
    return False


def similarity_to_known(domain: str) -> dict:
    """Calcula similaridade com todas as marcas e retorna o score máximo."""
    scores = {}
    for brand in KNOWN_BRANDS:
        ratio = SequenceMatcher(None, domain, brand).ratio()
        scores[brand] = ratio
    # Encontra maior similaridade
    best_brand, best_ratio = max(scores.items(), key=lambda x: x[1])
    return {"brand": best_brand, "ratio": best_ratio}


def analyze_content(url: str) -> dict:
    """Analisa HTML para detectar formulários de login e solicitações sensíveis."""
    issues = {"login_form": False, "sensitive_request": False}
    try:
        resp = requests.get(url, timeout=5)
        html = resp.text.lower()
        if re.search(r'<form[^>]*password', html):
            issues["login_form"] = True
        if re.search(r'(ssn|social security|cpf|credit card|bank account)', html):
            issues["sensitive_request"] = True
    except Exception:
        pass
    return issues


def analyze_advanced_heuristics(url: str) -> dict:
    """Executa todas as verificações de heurística avançada e retorna resultados."""
    if not url.lower().startswith(("http://", "https://")):
        url = "http://" + url
    domain = urlparse(url).netloc.lower()

    age_days = get_domain_age_days(domain)
    dyn_dns = detect_dynamic_dns(domain)
    ssl_info = analyze_ssl_info(domain)
    redirect = detect_redirects(url)
    sim = similarity_to_known(domain)
    content = analyze_content(url)

    # Flags de SSL
    expired = ssl_info.get("expired", False)
    match = ssl_info.get("match", False)

    # Agregando suspeitas
    suspicious = (
        (age_days is not None and age_days < 30) or
        dyn_dns or
        expired or
        not match or
        redirect or
        sim.get("ratio", 0) > 0.8 or
        content.get("login_form") or
        content.get("sensitive_request")
    )

    return {
        "suspicious": suspicious,
        "domain_age_days": age_days,
        "dynamic_dns": dyn_dns,
        "ssl": ssl_info,
        "redirect": redirect,
        "similarity": sim,
        "content_issues": content
    }