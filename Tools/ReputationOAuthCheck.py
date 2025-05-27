import socket
import dns.resolver
from urllib.parse import urlparse
import tldextract


# Listas DNSBL (DNS-based Block Lists) públicas
DNSBL_SERVERS = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "b.barracudacentral.org",
    "dnsbl.sorbs.net",
    "spamrbl.imp.ch"
]

# Lista de domínios OAuth legítimos
TRUSTED_OAUTH_PROVIDERS = [
    "accounts.google.com",
    "login.microsoftonline.com",
    "github.com",
    "login.facebook.com",
    "appleid.apple.com",
    "login.salesforce.com",
    "login.yahoo.com",
    "linkedin.com",
    "login.live.com",
    "slack.com"
]

#=======================Get IP from Domain========================
def get_ip_from_domain(url: str) -> str | None:
    """
    Obtém o IP associado ao domínio
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or parsed.path
        return socket.gethostbyname(hostname)
    except Exception:
        return None
#=================================================================

#=======================Check IP in DNSBL========================
def check_ip_dnsbl(ip: str) -> dict:
    """
    Verifica se o IP consta em listas públicas DNSBL.
    Não usa APIs externas, apenas consultas DNS.
    """
    results = {}
    try:
        reversed_ip = ".".join(ip.split(".")[::-1])
        for dnsbl in DNSBL_SERVERS:
            query = f"{reversed_ip}.{dnsbl}"
            try:
                dns.resolver.resolve(query, "A")
                results[dnsbl] = True
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                results[dnsbl] = False
            except Exception:
                results[dnsbl] = "Erro"
    except Exception:
        return {"error": "IP inválido ou falha na consulta DNSBL"}
    return results
#=================================================================

#=======================Detect Fake OAuth========================
def detect_fake_oauth(url: str) -> bool:
    """
    Verifica se a URL está tentando se passar por um serviço OAuth confiável.
    """
    parsed = urlparse(url)
    domain = tldextract.extract(parsed.netloc)
    full_domain = f"{domain.domain}.{domain.suffix}".lower()

    for trusted in TRUSTED_OAUTH_PROVIDERS:
        if trusted in parsed.netloc.lower() or trusted in full_domain:
            return False

    if any(x in url.lower() for x in ["oauth", "authorize", "auth", "login"]):
        return True

    return False
#=================================================================

#=======================Analyze Reputation and OAuth========================
def analyze_reputation_and_oauth(url: str) -> dict:
    """
    Executa:
    - Análise de reputação via DNSBL
    - Detecção de OAuth falso
    """
    ip = get_ip_from_domain(url)
    dnsbl_results = check_ip_dnsbl(ip) if ip else {"error": "IP não encontrado"}
    dnsbl_positive = any(v is True for v in dnsbl_results.values())

    fake_oauth = detect_fake_oauth(url)

    suspicious = dnsbl_positive or fake_oauth

    return {
        "suspicious": suspicious,
        "ip": ip,
        "dnsbl_results": dnsbl_results,
        "fake_oauth": fake_oauth
    }
