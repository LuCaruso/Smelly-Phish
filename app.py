import os
from datetime import datetime
from dotenv import load_dotenv
import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import plotly.graph_objects as go

from Tools.KnownSitesCheck import (
    extract_domain as extract_known_domain,
    _check_openphish,
    _check_phishtank,
    _check_google_safe_browsing,
)
from Tools.BasicHeuristicsCheck import analyze_heuristics
from Tools.AdvancedHeuristicsCheck import analyze_advanced_heuristics
from Tools.ReputationOAuthCheck import analyze_reputation_and_oauth

# Carrega variáveis de ambiente
load_dotenv()

# Inicializa histórico na sessão
if 'history' not in st.session_state:
    st.session_state.history = []

# Configura página
st.set_page_config(page_title="Smelly Phish", layout="centered", page_icon="🐟")

# CSS para os blocos de métricas
st.markdown("""
<style>
.module-block { padding: 1rem; border-radius: 0.5rem; margin-bottom: 1rem; }
.metric-block {
    display: inline-block;
    padding: 0.5rem 1rem;
    border-radius: 0.5rem;
    margin: 0.2rem;
    color: white;
    font-weight: bold;
    cursor: help;
}
.metric-true { background-color: #e74c3c; }
.metric-false { background-color: #27ae60; }
</style>
""", unsafe_allow_html=True)

def metric_block(label, is_risk, tooltip):
    """Gera um bloco de métrica com cor e tooltip."""
    color_class = 'metric-true' if is_risk else 'metric-false'
    return f"<div class='metric-block {color_class}' title='{tooltip}'>{label}</div>"

# Tooltips detalhados contendo explicação e risco
TOOLTIPS = {
    # 1. Bases Conhecidas
    "OpenPhish": (
        "Verifica se a URL consta no banco de dados da OpenPhish, uma das maiores bases "
        "de phishing do mundo. ⚠️ Se consta, é porque foi reportada e confirmada como phishing. Altíssima confiabilidade."
    ),
    "PhishTank": (
        "Consulta na PhishTank, plataforma colaborativa de denúncias de phishing. "
        "⚠️ Indicador direto de que a URL foi denunciada como phishing. Validação manual da comunidade."
    ),
    "Google Safe Browsing": (
        "Verifica se o domínio está listado como malicioso no Google Safe Browsing, usado "
        "por Chrome, Firefox e outros. ⚠️ Lista mantida pelo próprio Google; bloqueia malware, phishing e spam."
    ),

    # 2. Heurística Básica
    "Subdomínios": (
        "Conta quantos subdomínios existem antes do domínio principal. "
        "⚠️ Ataques de phishing usam muitos subdomínios para imitar marcas "
        "(ex.: secure-login-paypal.com.attacker.com). Quanto mais subdomínios, maior o risco."
    ),
    "Números no domínio": (
        "Detecta se há números no nome do domínio. ⚠️ Domínios legítimos raramente usam números aleatórios. "
        "Phishers usam para criar variações de marcas (ex.: bank123-login.com)."
    ),
    "Caracteres especiais": (
        "Detecta hífens, pontos ou substituições visuais (rn no lugar de m, 0 no lugar de o). "
        "⚠️ Alta incidência em domínios falsificados como micr0soft-login.com ou paypaI.com."
    ),

    # 3. Heurística Avançada
    "Idade domínio": (
        "Verifica quantos dias tem o domínio desde o registro (via WHOIS). "
        "⚠️ Domínios usados para phishing são frequentemente registrados há poucos dias. "
        "Um domínio muito novo (<30 dias) é um forte indicativo."
    ),
    "DNS Dinâmico": (
        "Verifica se o domínio usa provedores de DNS dinâmico (ex.: duckdns.org, no-ip.com). "
        "⚠️ DNS dinâmico permite que o IP mude facilmente; usado por atacantes para esconder localização, fugir de bloqueios e manter serviços ativos."
    ),
    "SSL Emissor": (
        "Analisa quem emitiu o certificado SSL. ⚠️ Certificados autoassinados ou de emissores desconhecidos são típicos de sites maliciosos."
    ),
    "SSL expira em": (
        "Valida a data de expiração do certificado SSL. ⚠️ Certificados expirados ou de curta duração (emitidos rapidamente) "
        "são comuns em ataques, especialmente com Let's Encrypt ou certificados gratuitos."
    ),
    "Cert Match": (
        "Verifica se o certificado SSL corresponde exatamente ao domínio. "
        "⚠️ Se não há correspondência, é um risco (ex.: certificado para *.wixsite.com não vale para outrodominio.com)."
    ),
    "Redirecionamentos": (
        "Detecta se há redirecionamentos HTTP ou JavaScript. "
        "⚠️ Usados para mascarar a URL de destino, enganando o usuário no clique e redirecionando depois."
    ),
    "Similaridade": (
        "Mede a similaridade do domínio analisado com marcas conhecidas (ex.: twitter.com, google.com). "
        "⚠️ Alta similaridade (>80%) indica tentativa de imitar uma marca legítima."
    ),
    "Formulário de login": (
        "Detecta se há formulário de login na página. ⚠️ A maioria dos ataques de phishing busca roubar credenciais; "
        "presença de login é alerta forte."
    ),
    "Solicitação sensível": (
        "Detecta campos solicitando dados sensíveis (CPF, cartão, senha). "
        "⚠️ Páginas maliciosas frequentemente pedem essas informações além das credenciais."
    ),

    # 4. Reputação & OAuth
    "IP": (
        "Verifica qual IP o domínio resolve. ⚠️ IPs hospedados em ASNs desconhecidos ou residenciais podem "
        "indicar infraestrutura temporária (ex.: VPS barata para phishing)."
    ),
    "DNSBL positivo": (
        "Verifica se o IP aparece em listas negras (DNS-based Blackhole Lists). "
        "⚠️ Se aparece, é porque já foi usado para spam, malware, phishing ou outras atividades maliciosas."
    ),
    "OAuth falso": (
        "Detecta se a URL tenta simular telas de login OAuth (Google, Microsoft, Apple, etc.). "
        "⚠️ Ataques que simulam OAuth são extremamente perigosos — podem roubar acesso a contas e sistemas corporativos."
    ),
}

# Pesos para as demais métricas
WEIGHTS = {
    "OpenPhish":            80,  
    "PhishTank":            80,  
    "Google Safe Browsing": 80,  

    "Subdomínios":          40,   
    "Números no domínio":   20,   
    "Caracteres especiais": 40,   

    "Idade domínio":        60,
    "Redirecionamentos":    30,
    "Similaridade":         80,

    "DNS Dinâmico":         30,   
    "SSL Emissor":          20,   
    "SSL expira em":        30,   
    "Cert Match":           20,   

    "Formulário de login":  25,   
    "Solicitação sensível": 25,   

    "DNSBL positivo":       30,   
    "OAuth falso":          50   
}


# Título e input
st.title("🐟💨 Smelly Phish – Detector de Phishing")
url = st.text_input("Digite uma URL para verificar")

if st.button("Verificar") and url:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Execução dos checks
    domain    = extract_known_domain(url)
    op_flag   = _check_openphish(domain)
    pt_flag   = _check_phishtank(domain)
    gsb_flag  = _check_google_safe_browsing(url)
    h         = analyze_heuristics(url)
    t         = analyze_advanced_heuristics(url)
    r         = analyze_reputation_and_oauth(url)
    dnsbl_pos = any(v is True for v in r['dnsbl_results'].values())

    # 1. Bases Conhecidas
    st.markdown(
        f"<div class='module-block' style='background-color:{'#f8d7da' if (op_flag or pt_flag or gsb_flag) else '#d4edda'};color: black;'>"
        "<strong>🔍 Verificação em Bases Conhecidas:</strong><br>" +
        "".join([
            metric_block("OpenPhish", op_flag, TOOLTIPS["OpenPhish"]),
            metric_block("PhishTank", pt_flag, TOOLTIPS["PhishTank"]),
            metric_block("Google Safe Browsing", gsb_flag, TOOLTIPS["Google Safe Browsing"])
        ]) +
        "</div>", unsafe_allow_html=True
    )

    # 2. Heurística Básica
    st.markdown(
        f"<div class='module-block' style='background-color:{'#f8d7da' if h['suspicious'] else '#d4edda'}; color: black;'>"
        "<strong>🧠 Análise Heurística Básica:</strong><br>" +
        "".join([
            metric_block(f"Subdomínios ({h['num_sub']})", h['num_sub'] > 2, TOOLTIPS["Subdomínios"]),
            metric_block("Números no domínio", h['number_sub'], TOOLTIPS["Números no domínio"]),
            metric_block(f"Caracteres especiais: {', '.join(h['specials']) or 'Nenhum'}", bool(h['specials']), TOOLTIPS["Caracteres especiais"])
        ]) +
        "</div>", unsafe_allow_html=True
    )

    # 3. Heurística Avançada
    ssl = t['ssl']
    sim = t['similarity']
    st.markdown(
        f"<div class='module-block' style='background-color:{'#f8d7da' if t['suspicious'] else '#d4edda'};color: black;'>"
        "<strong>🔎 Análise Heurística Avançada:</strong><br>" +
        "".join([
            metric_block(f"Idade domínio ({t['domain_age_days']} dias)", t['domain_age_days'] is not None and t['domain_age_days'] < 30, TOOLTIPS["Idade domínio"]),
            metric_block("DNS Dinâmico", t['dynamic_dns'], TOOLTIPS["DNS Dinâmico"]),
            metric_block(f"SSL Emissor: {ssl['issuer'] or 'Desconhecido'}", ssl['issuer'] is None, TOOLTIPS["SSL Emissor"]),
            metric_block(f"SSL expira em: {ssl['expires']} ({ssl['days_left']} dias)", ssl['expired'], TOOLTIPS["SSL expira em"]),
            metric_block("Cert Match", not ssl['match'], TOOLTIPS["Cert Match"]),
            metric_block(f"Redirecionamentos: {'Sim' if t['redirect'] else 'Não'}", t['redirect'], TOOLTIPS["Redirecionamentos"]),
            metric_block(f"Similaridade com {sim['brand']} ({sim['ratio']:.2f})", sim['ratio'] > 0.8, TOOLTIPS["Similaridade"]),
            metric_block("Formulário de login", t['content_issues']['login_form'], TOOLTIPS["Formulário de login"]),
            metric_block("Solicitação sensível", t['content_issues']['sensitive_request'], TOOLTIPS["Solicitação sensível"])
        ]) +
        "</div>", unsafe_allow_html=True
    )

    # 4. Reputação & OAuth
    st.markdown(
        f"<div class='module-block' style='background-color:{'#f8d7da' if r['suspicious'] else '#d4edda'};color: black;'>"
        "<strong>🌍 Análise de Reputação & OAuth:</strong><br>" +
        "".join([
            metric_block(f"DNSBL positivo: {'Sim' if dnsbl_pos else 'Não'}", dnsbl_pos, TOOLTIPS["DNSBL positivo"]),
            metric_block("OAuth falso detectado" if r['fake_oauth'] else "OAuth legítimo", r['fake_oauth'], TOOLTIPS["OAuth falso"])
        ]) +
        "</div>", unsafe_allow_html=True
    )
    # Atualiza histórico
    st.session_state.history.append({
        'Timestamp': timestamp,
        'URL': url,
        'OpenPhish': op_flag,
        'PhishTank': pt_flag,
        'Google Safe Browsing': gsb_flag,
        'Suspeita Básica': h['suspicious'],
        'Subdomínios': h['num_sub'],
        'Números no domínio': h['number_sub'],
        'Caracteres especiais': ','.join(h['specials']),
        'Suspeita Avançada': t['suspicious'],
        'Idade domínio (dias)': t['domain_age_days'],
        'DNS Dinâmico': t['dynamic_dns'],
        'Emissor SSL': ssl['issuer'],
        'Expira em': ssl['expires'],
        'Cert match': ssl['match'],
        'Redirecionamentos': t['redirect'],
        'Similaridade marca': sim['brand'],
        'Similaridade score': sim['ratio'],
        'Formulário de login': t['content_issues']['login_form'],
        'Solicitação sensível': t['content_issues']['sensitive_request'],
        'DNSBL positivo': dnsbl_pos,
        'OAuth falso': r['fake_oauth']
    })

    # Exibe histórico e botão de download
    st.subheader("Histórico de URLs verificadas")
    df = pd.DataFrame(st.session_state.history)
    st.dataframe(df)
    csv = df.to_csv(index=False).encode('utf-8')
    st.download_button("Exportar CSV", data=csv, file_name='history_phishing.csv', mime='text/csv')

    # Gráfico de Pizza
    last = st.session_state.history[-1]
    known_flags = sum([int(last['OpenPhish']), int(last['PhishTank']), int(last['Google Safe Browsing'])])
    basic_flags = sum([int(last['Subdomínios'] > 2), int(last['Números no domínio']), int(bool(last['Caracteres especiais']))])
    adv_flags = sum([
        last['Idade domínio (dias)'] is not None and last['Idade domínio (dias)'] < 30,
        last['DNS Dinâmico'], not last['Cert match'], last['Redirecionamentos'],
        last['Similaridade score'] > 0.8, last['Formulário de login'], last['Solicitação sensível']
    ])
    rep_flags = sum([int(last['DNSBL positivo']), int(last['OAuth falso'])])
    total_flags = known_flags + basic_flags + adv_flags + rep_flags

    labels = [
        'Bases Conhecidas',
        'Heurística Básica',
        'Heurística Avançada',
        'Reputação & OAuth',
    ]
    sizes = [known_flags, basic_flags, adv_flags, rep_flags]
    colors = ['#1ABC9C', '#E67E22', '#8E44AD', '#3498DB']

    st.markdown(
        "<div class='module-block' style='background-color:#303030; color:white; text-align:center; padding:1rem;'>"
        "<h3 style='margin:0;'>Distribuição de Flags de Phishing por Categoria</h3>"
        "</div>",
        unsafe_allow_html=True
    )
    def make_autopct(total):
        def autopct(pct):
            val = int(round(pct * total / 100.0))
            return str(val)
        return autopct
    fig, ax = plt.subplots(figsize=(6,6), facecolor='#303030')
    fig.patch.set_facecolor('#303030')
    patches, texts, autotexts = ax.pie(sizes, labels=None, autopct=make_autopct(total_flags), startangle=140,
                                       colors=colors, wedgeprops={'edgecolor': 'white', 'linewidth': 1})
    ax.axis('equal')
    legend = ax.legend(patches, [f"{label} ({count})" for label, count in zip(labels, sizes)], title='Categorias', title_fontsize='large',
                       loc='upper center', bbox_to_anchor=(0.5, -0.1), ncol=2,
                       frameon=False, fontsize='medium', labelcolor='white')
    legend.get_title().set_color('white')
    for txt in texts: txt.set_visible(False)
    for autotxt in autotexts: autotxt.set_color('white'); autotxt.set_weight('bold')
    plt.tight_layout(rect=[0,0,1,0.85])
    st.pyplot(fig)
    st.markdown("</div>", unsafe_allow_html=True)

    # Gauge de probabilidade de phishing
    score = 0

    # soma os pesos das demais métricas
    flags = {
        "OpenPhish":            op_flag,
        "PhishTank":            pt_flag,
        "Google Safe Browsing": gsb_flag,
        "Subdomínios":          h['num_sub'] > 2,
        "Números no domínio":   h['number_sub'],
        "Caracteres especiais": bool(h['specials']),
        "DNS Dinâmico":         t['dynamic_dns'],
        "Idade domínio":          t['domain_age_days'] is not None and t['domain_age_days'] < 30,
        "SSL Emissor":          ssl['issuer'] is None,
        "SSL expira em":        ssl['expired'],
        "Cert Match":           not ssl['match'],
        "Redirecionamentos":    t['redirect'],
        "Similaridade":       sim['ratio'] > 0.8,     
        "Formulário de login":  t['content_issues']['login_form'],
        "Solicitação sensível": t['content_issues']['sensitive_request'],
        "DNSBL positivo":       dnsbl_pos,
        "OAuth falso":          r['fake_oauth'],
    }
    for name, hit in flags.items():
        if hit:
            score += WEIGHTS.get(name, 0)

    # cap em 100%
    if score > 100:
        score = 100

    st.markdown(
        "<div class='module-block' style='background-color:#303030; color:white; text-align:center; padding-bottom:1rem;'>"
        "<h3 style='margin:0; padding-bottom:0.5rem;'>Probabilidade do Site ser Phishing</h3>"
        , unsafe_allow_html=True
    )

    # Escolhe cor vibrante conforme score
    if score < 50:
        bar_color = "#27ae64"   # verde vibrante
        steps = [
            {'range': [0, 50], 'color': "#00ff15"},
            {'range': [50, 80], 'color': "#fff700"},
            {'range': [80, 100], 'color': "#fe0000"},
        ]
    elif score < 80:
        bar_color = "#ff9d00"   # laranja vibrante
        steps = [
            {'range': [0, 50], 'color': "#00ff15"},
            {'range': [50, 80], 'color': "#fff700"},
            {'range': [80, 100], 'color': "#fe0000"},
        ]
    else:
        bar_color = '#c0392b'   # vermelho escuro
        steps = [
            {'range': [0, 50], 'color': "#00ff15"},
            {'range': [50, 80], 'color': "#fff700"},
            {'range': [80, 100], 'color': "#fe0000"},
        ]

    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        gauge={
            'axis': {'range': [0, 100], 'tickcolor': 'lightgray', 'tickfont': {'color':'white'}},
            'bar': {'color': bar_color, 'thickness': 0.25},
            'bgcolor': 'rgba(0,0,0,0)',
            'steps': steps,
            'threshold': {
                'line': {'color': bar_color, 'width': 4},
                'thickness': 0.8,
                'value': score
            }
        },
        number={'suffix': '%', 'font': {'size': 32, 'color': 'white'}}
    ))

    fig.update_layout(
        paper_bgcolor='#303030',     
        plot_bgcolor='#303030',        
        margin={'t': 0, 'b': 0, 'l': 0, 'r': 0}
    )

    st.plotly_chart(fig, use_container_width=True)
    st.markdown("</div>", unsafe_allow_html=True)