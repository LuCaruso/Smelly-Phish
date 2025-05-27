import os
import requests
import tldextract
from urllib.parse import urlparse
import csv
from io import StringIO

# URLs das bases públicas
_OPENPHISH_FEED = "https://openphish.com/feed.txt"
_PHISHTANK_CSV_URL = "https://data.phishtank.com/data/online-valid.csv"
_GSB_API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

#=======================Extract Domain====================================
def extract_domain(url: str) -> str:
    """
    Extrai o domínio raiz (sem subdomínios) de uma URL.
    """
    if not url.lower().startswith(("http://", "https://")):
        url = "http://" + url
    parsed = urlparse(url)
    ext = tldextract.extract(parsed.netloc)
    return f"{ext.domain}.{ext.suffix}"
#==========================================================================

#=======================Check Public Phishing Databases====================
def _check_openphish(domain: str) -> bool:
    """
    Verifica se o domínio consta no feed público do OpenPhish.
    """
    try:
        resp = requests.get(_OPENPHISH_FEED, timeout=5)
        resp.raise_for_status()
        for line in resp.text.splitlines():
            if extract_domain(line) == domain:
                return True
    except requests.RequestException:
        pass
    return False
#==========================================================================

#=======================Load PhishTank Bulk Data===========================
def load_phishtank_bulk() -> set:
    """
    Baixa o CSV diário de phishes validados do PhishTank e retorna um set de domínios.
    """
    try:
        resp = requests.get(_PHISHTANK_CSV_URL, timeout=10)
        resp.raise_for_status()
        reader = csv.DictReader(StringIO(resp.text))
        return {extract_domain(row['url']) for row in reader if row.get('url')}
    except requests.RequestException:
        return set()
# Carrega uma vez, no início
_PHISHTANK_DOMAINS = load_phishtank_bulk()
#==========================================================================

#=======================Check PhishTank Local Dump=========================
def _check_phishtank(domain: str) -> bool:
    """
    Verifica localmente se o domínio consta no dump CSV do PhishTank.
    """
    return domain in _PHISHTANK_DOMAINS
#==========================================================================

#=======================Check Google Safe Browsing=========================
def _check_google_safe_browsing(url: str) -> bool:
    """
    Consulta a API Google Safe Browsing v4 para verificar ameaças.
    Exige chave GOOGLE_SAFE_BROWSING_API_KEY no ambiente.
    """
    key = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY', '')
    if not key:
        return False
    payload = {
        'client': {
            'clientId': 'smelly-phish-app',
            'clientVersion': '1.0'
        },
        'threatInfo': {
            'threatTypes': [
                'MALWARE',
                'SOCIAL_ENGINEERING',
                'UNWANTED_SOFTWARE',
                'POTENTIALLY_HARMFUL_APPLICATION'
            ],
            'platformTypes': ['ANY_PLATFORM'],
            'threatEntryTypes': ['URL'],
            'threatEntries': [{'url': url}]
        }
    }
    try:
        resp = requests.post(
            f"{_GSB_API_URL}?key={key}",
            json=payload,
            timeout=5
        )
        resp.raise_for_status()
        data = resp.json()
        return bool(data.get('matches'))
    except (requests.RequestException, ValueError):
        return False
#==========================================================================

#=======================Check All Databases================================
def check_databases(url: str) -> (bool, list):
    """
    Verifica se a URL/domínio consta em alguma base pública de phishing:
      - OpenPhish
      - PhishTank (bulk CSV)
      - Google Safe Browsing

    Retorna tupla (encontrado: bool, fontes: list[str]) indicando True se phishing e as bases que reportaram.
    """
    if not url.lower().startswith(("http://", "https://")):
        url = "http://" + url

    domain = extract_domain(url)
    fontes = []

    if _check_openphish(domain):
        fontes.append("OpenPhish")
    if _check_phishtank(domain):
        fontes.append("PhishTank")
    if _check_google_safe_browsing(url):
        fontes.append("Google Safe Browsing")

    return (bool(fontes), fontes)
#==========================================================================