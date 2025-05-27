import socket
import ssl
import requests
import re
import whois
from datetime import datetime
from urllib.parse import urlparse
import Levenshtein
from io import BytesIO
from datetime import datetime
import tldextract
import dns.resolver


# Lista de provedores de DNS dinâmico comuns
DYNAMIC_DNS_PROVIDERS = [
    "no-ip.org", "no-ip.com", "dyndns.org", "dyn.com", "duckdns.org", "dynu.com",
    "changeip.com", "freedns.afraid.org", "hopto.org", "zapto.org", "dnsdynamic.org",
    "myftp.org", "serveftp.com", "serveftp.net", "sytes.net"
]
# Lista de marcas conhecidas para checar similaridade
KNOWN_BRANDS = [
    "google.com", "gmail.com", "facebook.com", "youtube.com", "twitter.com",
    "instagram.com", "linkedin.com", "wikipedia.org", "amazon.com",
    "paypal.com", "microsoft.com", "live.com", "outlook.com", "yahoo.com",
    "apple.com", "netflix.com", "spotify.com", "adobe.com",
    "github.com", "dropbox.com", "slack.com", "shopify.com",
    "salesforce.com", "wordpress.com", "pinterest.com", "reddit.com",
    "tumblr.com", "quora.com", "stackexchange.com", "stackoverflow.com",
    "azure.microsoft.com", "cloudflare.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "hsbc.com",
    "citibank.com", "barclays.co.uk",
    "google.com.br", "mercadolivre.com.br", "mercadopago.com.br", "uol.com.br",
    "globo.com", "terra.com.br", "ig.com.br", "olx.com.br",
    "bancodobrasil.com.br", "bb.com.br", "itau.com.br", "bradesco.com.br",
    "caixa.gov.br", "nubank.com.br", "c6bank.com.br", "bancointer.com.br",
    "banrisul.com.br", "santander.com.br", "xp.com.br", "pagseguro.uol.com.br",
    "ebay.com.br", "magazineluiza.com.br", "americanas.com.br", "submarino.com.br",
    "netshoes.com.br", "vivo.com.br", "claro.com.br", "oi.com.br", "tim.com.br",
    "receita.fazenda.gov.br", "gov.br", "sebrae.com.br",
]


#=======================Get Domain Age========================
def get_domain_age_days(url: str) -> int | None:
    """
    Retorna a idade do domínio em dias, dado uma URL completa ou domínio.
    """
    try:
        # Extrair domínio base da URL
        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}"
        
        # Consultar WHOIS
        w = whois.whois(domain)
        creation = w.creation_date

        # Resolver possíveis listas de datas
        if isinstance(creation, list):
            creation = [d for d in creation if d is not None]
            if creation:
                creation = min(creation)
            else:
                return None

        # Calcular idade em dias
        if isinstance(creation, datetime):
            return (datetime.utcnow() - creation).days

    except Exception as e:
        print(f"[WHOIS ERROR] {e}")

    return None
#===============================================================

#=======================Detect Dynamic DNS========================
def detect_dynamic_dns(full_domain: str) -> bool:
    """
    Verifica se o domínio está usando DNS dinâmico baseado em registros NS e CNAME.
    """
    ext = tldextract.extract(full_domain)
    domain = f"{ext.domain}.{ext.suffix}"

    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        ns_hosts = [str(r.target).lower() for r in ns_records]

        for ns in ns_hosts:
            if any(provider in ns for provider in DYNAMIC_DNS_PROVIDERS):
                print(f"[DNS DETECTED] NS associado a DNS dinâmico: {ns}")
                return True

        # Verificar CNAME (se existir)
        try:
            cname_records = dns.resolver.resolve(domain, 'CNAME')
            for cname in cname_records:
                cname_target = str(cname.target).lower()
                if any(provider in cname_target for provider in DYNAMIC_DNS_PROVIDERS):
                    print(f"[DNS DETECTED] CNAME associado a DNS dinâmico: {cname_target}")
                    return True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            pass  # Sem CNAME, normal em domínios raiz

    except Exception as e:
        print(f"[DNS ERROR] {e}")

    return False
#==================================================================

#=======================SSL Certificate Analysis========================
def analyze_ssl_info(domain: str) -> dict:
    """
    Retorna informações detalhadas do certificado SSL do domínio.
    """
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

            # Verifica correspondência de domínio (com suporte a wildcard)
            san = cert.get('subjectAltName', ())
            cert_domains = [entry[1].lower() for entry in san if entry[0] == 'DNS']

            domain = domain.lower()
            match = False
            for cd in cert_domains:
                if cd.startswith("*."):
                    # Verifica se o domínio termina com o restante do wildcard
                    if domain.endswith(cd[1:]):
                        match = True
                        break
                if domain == cd:
                    match = True
                    break

            info["match"] = match

    except Exception as e:
        print(f"[SSL ERROR] {e}")

    return info
#==================================================================

#=======================Advanced Heuristics Analysis========================
def detect_redirects(url: str) -> bool:
    """
    Detecta redirecionamentos suspeitos na URL.
    """
    try:
        resp = requests.get(url, timeout=5, allow_redirects=True)
        if resp.history:
            orig = urlparse(url).netloc.lower()
            final = urlparse(resp.url).netloc.lower()
            return orig != final
    except Exception:
        pass
    return False
#==================================================================

#=======================Similarity to Known Brands========================
def similarity_to_known(domain: str) -> dict:
    """
    Calcula similaridade com todas as marcas usando Levenshtein.
    """
    # Normaliza removendo www. do início, se presente
    d = domain.lower()
    if d.startswith("www."):
        d = d[len("www."):]

    best_brand = None
    best_ratio = 0.0

    for brand in KNOWN_BRANDS:
        # compara com domínio base
        ratio = Levenshtein.ratio(d, brand)
        if ratio > best_ratio:
            best_ratio, best_brand = ratio, brand

    # Se for match perfeito, zera
    if best_ratio == 1.0:
        best_ratio = 0.0

    return {"brand": best_brand, "ratio": best_ratio}
#==================================================================

#=======================Content Analysis for Login Forms and Sensitive Requests========================
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
#==================================================================

#=======================Main Function for Advanced Heuristics Analysis========================
def analyze_advanced_heuristics(url: str) -> dict:
    """
    Executa todas as verificações de heurística avançada e retorna resultados
    """
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