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


# Carrega variáveis de ambiente
load_dotenv()

# Inicializa histórico
if 'history' not in st.session_state:
    st.session_state.history = []

# Configuração da página
st.set_page_config(page_title="Detecção de Phishing", layout="centered", page_icon="🛡️")

# CSS personalizado
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


# Função para criar sub-blocos
def metric_block(label, is_risk, tooltip):
    color_class = 'metric-true' if is_risk else 'metric-false'
    return f"<div class='metric-block {color_class}' title='{tooltip}'>{label}</div>"


st.title("Smelly Phish – Detector de Phishing")
url = st.text_input("Digite uma URL para verificar")


if st.button("Verificar") and url:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 1) Verificação em Bases Conhecidas
    domain = extract_known_domain(url)
    op_flag = _check_openphish(domain)
    pt_flag = _check_phishtank(domain)
    gsb_flag = _check_google_safe_browsing(url)
    found_known = op_flag or pt_flag or gsb_flag
    color = "#f8d7da" if found_known else "#d4edda"
    text_color = "#721c24" if found_known else "#155724"
    st.markdown(
        f"<div class='module-block' style='background-color:{color}; color:{text_color};'>"
        f"<strong>Verificação em Bases Conhecidas:</strong><br>"
        +
        "".join([
            metric_block("OpenPhish", op_flag, "OpenPhish é uma base de dados que mantém uma lista atualizada de URLs confirmadas como phishing. Se a URL aparecer aqui, ela já foi identificada como uma ameaça real por especialistas na área."),
            metric_block("PhishTank", pt_flag, "PhishTank é um serviço colaborativo onde usuários e analistas reportam e validam URLs maliciosas. Se a URL estiver nesta base, é um forte indicativo de que o site já foi utilizado em ataques."),
            metric_block("Google Safe Browsing", gsb_flag, "O Google Safe Browsing detecta sites que hospedam malware, phishing e outras ameaças. Se o site consta como inseguro, ele representa um risco significativo para os usuários.")
        ]) +
        "</div>",
        unsafe_allow_html=True
    )

    # 2) Análise Heurística Básica
    h = analyze_heuristics(url)
    color = "#f8d7da" if h["suspicious"] else "#d4edda"
    text_color = "#721c24" if h["suspicious"] else "#155724"
    st.markdown(
        f"<div class='module-block' style='background-color:{color}; color:{text_color};'>"
        f"<strong>Análise Heurística Básica:</strong><br>"
        +
        "".join([
            metric_block(f"Subdomínios ({h['num_sub']})", h['num_sub'] > 2, "O uso excessivo de subdomínios (ex.: login.payments.secure.bank.com) pode ser uma tentativa de enganar usuários, criando uma aparência legítima através de estruturas complexas no nome do domínio."),
            metric_block("Números no domínio", h['number_sub'], "Números são frequentemente usados em domínios falsificados (ex.: facebook123.com) porque os atacantes não conseguem registrar os domínios oficiais. Essa prática é comum para evitar detecção ou por falta de disponibilidade de nomes legítimos."),
            metric_block(
                f"Caracteres especiais: {', '.join(h['specials']) if h['specials'] else 'Nenhum'}",
                bool(h['specials']),
                "Caracteres como hífens, sublinhados ou até substituições visuais (ex.: 'pay-pal.com' ou 'secure_login.net') são frequentemente utilizados por criminosos para criar domínios que imitam empresas legítimas."
            )
        ]) +
        "</div>",
        unsafe_allow_html=True
    )

    # 3) Análise Heurística Avançada
    t = analyze_advanced_heuristics(url)
    ssl = t['ssl']
    sim = t['similarity']
    found_adv = t['suspicious']
    color = "#f8d7da" if found_adv else "#d4edda"
    text_color = "#721c24" if found_adv else "#155724"
    st.markdown(
        f"<div class='module-block' style='background-color:{color}; color:{text_color};'>"
        f"<strong>Análise Heurística Avançada:</strong><br>"
        +
        "".join([
            metric_block(f"Idade domínio ({t['domain_age_days']} dias)", t['domain_age_days'] is not None and t['domain_age_days'] < 30, "Domínios muito novos (menos de 30 dias) são altamente suspeitos, pois campanhas de phishing costumam usar domínios recém-registrados para evitar bloqueios e maximizar a efetividade antes que sejam denunciados."),
            metric_block("DNS Dinâmico", t['dynamic_dns'], "O uso de serviços de DNS dinâmico permite que os criminosos mudem rapidamente o endereço IP do servidor onde o site malicioso está hospedado. Isso dificulta a detecção e o bloqueio por soluções de segurança."),
            metric_block(f"SSL Emissor: {ssl['issuer'] or 'Desconhecido'}", ssl['issuer'] is None, "A ausência de um certificado SSL válido ou emitido por uma autoridade reconhecida significa que a conexão com o site não é segura. Sites legítimos sempre possuem SSL confiável."),
            metric_block(f"SSL expira em: {ssl['expires']} ({ssl['days_left']} dias)", ssl['expired'], "Certificados SSL expirados indicam falta de manutenção e podem ser um sinal de site abandonado ou malicioso."),
            metric_block("Cert Match", not ssl['match'], "O certificado SSL precisa estar vinculado exatamente ao domínio acessado. Quando não há correspondência, isso indica uma tentativa de mascaramento ou um erro proposital para enganar usuários."),
            metric_block(f"Redirecionamentos: {'Sim' if t['redirect'] else 'Não'}", t['redirect'], "Muitos ataques de phishing utilizam redirecionamentos para disfarçar a origem do site, levar o usuário a um domínio malicioso após passar por domínios aparentemente legítimos."),
            metric_block(f"Similaridade com {sim['brand']} ({sim['ratio']:.2f})", sim['ratio'] > 0.8, "Se a URL, o conteúdo ou o domínio tem alta similaridade textual ou visual com uma marca conhecida, é provável que o objetivo seja se passar por essa empresa e enganar os visitantes."),
            metric_block("Formulário de login", t['content_issues']['login_form'], "Phishing geralmente envolve a captura de credenciais. Se o site contém um formulário de login, especialmente em páginas não esperadas, é um forte indicativo de que tenta roubar informações de acesso."),
            metric_block("Solicitação sensível", t['content_issues']['sensitive_request'], "Se o site solicita informações sensíveis (como CPF, senhas, dados bancários) de forma inesperada, especialmente sem protocolos de segurança adequados, isso representa risco elevado de fraude.")
        ]) +
        "</div>",
        unsafe_allow_html=True
    )

    # Atualiza histórico
    st.session_state.history = [e for e in st.session_state.history if e['URL'] != url]
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
        'Op': op_flag, 'Pt': pt_flag, 'Gsb': gsb_flag,
        'Subdom>2': h['num_sub'] > 2, 'NumSub': h['number_sub'], 'SpecChar': bool(h['specials']),
        'Age<30': t['domain_age_days'] is not None and t['domain_age_days'] < 30,
        'DynDNS': t['dynamic_dns'], 'SSLfails': not ssl['match'], 'Redirect': t['redirect'],
        'HighSim': sim['ratio'] > 0.8, 'Form': t['content_issues']['login_form'], 'Sensitive': t['content_issues']['sensitive_request']
    })


# Exibe histórico e botão de exportação
if st.session_state.history:
    st.subheader("Histórico de URLs verificadas")
    df = pd.DataFrame(st.session_state.history)
    st.dataframe(df)
    csv = df.to_csv(index=False).encode('utf-8')
    st.download_button(
        label="Exportar CSV",
        data=csv,
        file_name='history_phishing.csv',
        mime='text/csv'
    )

# Gráfico de Pizza de Flags por Categoria para a última URL, em bloco escuro
if st.session_state.history:
    last = st.session_state.history[-1]

    known_flags = sum([
        int(last['OpenPhish']), int(last['PhishTank']), int(last['Google Safe Browsing'])
    ])
    basic_flags = sum([
        int(last['Subdomínios'] > 2), int(last['Números no domínio']), int(bool(last['Caracteres especiais']))
    ])
    adv_checks = [
        last['Idade domínio (dias)'] is not None and last['Idade domínio (dias)'] < 30,
        last['DNS Dinâmico'], not last['Cert match'], last['Redirecionamentos'],
        last['Similaridade score'] > 0.8, last['Formulário de login'], last['Solicitação sensível'],
    ]
    adv_flags = sum(int(flag) for flag in adv_checks)

    labels = [
        f'Bases Conhecidas ({known_flags})',
        f'Heurística Básica ({basic_flags})',
        f'Heurística Avançada ({adv_flags})',
    ]
    sizes = [known_flags, basic_flags, adv_flags]
    colors = ['#1ABC9C', '#E67E22', '#8E44AD']

    # bloco escuro centralizado
    st.markdown(
        "<div class='module-block' style='background-color:#303030; text-align:center;'>",
        unsafe_allow_html=True
    )

    fig, ax = plt.subplots(figsize=(6,6), facecolor='#303030')
    fig.patch.set_facecolor('#303030')
    patches, texts, autotexts = ax.pie(
        sizes,
        labels=None,
        autopct='%1.0f',
        startangle=140,
        colors=colors,
        wedgeprops={'edgecolor': 'white', 'linewidth': 1}
    )
    ax.set_title(
        'Distribuição de Flags de Phishing por Categoria',
        y=1.2, color='white', pad=5, fontweight='bold'
    )
    ax.axis('equal')  # mantém círculo

    # legenda abaixo
    legend = ax.legend(
        patches, labels,
        title='Categorias', title_fontsize='large',
        loc='upper center', bbox_to_anchor=(0.5, -0.1), ncol=3,
        frameon=False, fontsize='medium', labelcolor='white'
    )
    legend.get_title().set_color('white')

    for txt in texts:
        txt.set_visible(False)
    for autotxt in autotexts:
        autotxt.set_color('white')
        autotxt.set_weight('bold')

    plt.tight_layout(rect=[0,0,1,0.85])
    st.pyplot(fig)
    st.markdown("</div>", unsafe_allow_html=True)

# ——— Gauge de Probabilidade de Phishing ———
if st.session_state.history:
    
    last = st.session_state.history[-1]
    # lista de 13 métricas booleanas
    bool_keys = [
        'Op','Pt','Gsb',
        'Subdom>2','NumSub','SpecChar',
        'Age<30','DynDNS','SSLfails',
        'Redirect','HighSim','Form','Sensitive'
    ]
    total = len(bool_keys)
    score = sum(int(last[k]) for k in bool_keys) / total * 100

    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        gauge={
            'axis': {'range': [0, 100]},
            'bar': {'color': 'white'},
            'steps': [
                {'range': [0, 50], 'color': 'green'},
                {'range': [50, 80], 'color': 'yellow'},
                {'range': [80, 100], 'color': 'red'},
            ]
        },
        number={'suffix': "%"}
    ))
    fig.update_layout(
        title={
            'text': "Probabilidade do Site ser Phishing",
            'x': 0.5,
            'xanchor': 'center',
            'yanchor': 'top'
        },
        title_font=dict(size=20),
        margin={'t': 50, 'b': 0, 'l': 0, 'r': 0},
        paper_bgcolor="#303030",
        font={'color': 'white'}
    )

    st.markdown(
        "<div class='module-block' style='background-color:#303030; text-align:center;'>",
        unsafe_allow_html=True
    )
    st.plotly_chart(fig, use_container_width=True)
    st.markdown("</div>", unsafe_allow_html=True)
