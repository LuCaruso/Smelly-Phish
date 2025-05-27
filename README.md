# 🐟💨 Smelly Phish – Detector de Phishing

Smelly Phish é uma ferramenta interativa desenvolvida em Python e Streamlit para análise e detecção de URLs potencialmente maliciosas, focando especialmente em ataques de phishing. O aplicativo utiliza uma combinação de checagem em bases públicas, análise heurística básica e heurística avançada para avaliar o risco associado a uma URL.

---

## 🚀 Como Rodar Localmente

1. Clone este repositório:

```bash
git clone https://github.com/LuCaruso/Smelly-Phish.git
cd smelly-phish
```

2. Crie um ambiente virtual:

```bash
python -m venv env
```

3. Ative o ambiente virtual:

- No Windows:

```bash
.\env\Scripts\Activate.ps1
```

- No macOS/Linux:

```bash
source env/bin/activate
```

4. Atualize o pip e instale as dependências:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

5. Execute o aplicativo:

```bash
streamlit run app.py
```

---

## 🔑 Configuração (Opcional)

Para utilizar funcionalidades opcionais, configure suas chaves de API no arquivo .env:
```
GOOGLE_SAFE_BROWSING_API_KEY=SuaChaveAqui
IPINFO_TOKEN=SeuTokenIPInfo
```

---

## 🎯 Funcionalidades

### 1️⃣ **Verificação em Bases Conhecidas**
- 🔍 Verifica se o domínio consta nas principais bases públicas de phishing:
  - OpenPhish
  - PhishTank
  - Google Safe Browsing

### 2️⃣ **Análise Heurística Básica**
- 🔗 **Quantidade de subdomínios:** Muitos subdomínios podem indicar tentativa de disfarce.
- 🔢 **Presença de números no domínio:** Domínios com números frequentemente tentam imitar marcas legítimas.
- ✳️ **Uso de caracteres especiais:** Hífens, sublinhados e outros símbolos podem ser usados para enganar visualmente.

### 3️⃣ **Análise Heurística Avançada**
- 📅 **Idade do domínio:** Domínios com menos de 30 dias são altamente suspeitos.
- 🌐 **Uso de DNS dinâmico:** Detecta se o domínio utiliza serviços como no-ip, duckdns, dyndns.
- 🔐 **Análise de SSL:** Verifica emissor, validade, expiração e correspondência do certificado.
- 🔀 **Redirecionamentos:** Sites que redirecionam podem mascarar sua origem.
- 🏷️ **Similaridade com marcas conhecidas:** Avalia semelhança textual com empresas famosas.
- 🛑 **Análise de conteúdo:** Detecta formulários de login e solicitações de dados sensíveis.

### 4️⃣ **Análise de Reputação & OAuth**
- 🌍 **DNSBL:** verifica se o IP do domínio consta em listas negras públicas.
- 🔑 **OAuth falso:** detecta tentativas de imitar provedores OAuth conhecidos.

### 5️⃣ **Histórico e Exportação**
- 🔗 Mantém o histórico das URLs analisadas na sessão atual.
- 📥 Permite exportar o histórico em formato CSV.

### 6️⃣ **Relatórios Visuais**
- 📊 **Gráfico de Pizza:** Mostra a distribuição dos riscos por categoria.
- 🎯 **Gauge de Probabilidade:** Indica a probabilidade da URL ser phishing de 0% a 100%.



### 💡 Dica de Uso
- Para saber mais sobre cada métrica e os riscos associados, basta passar o mouse sobre o bloco correspondente na interface – um tooltip exibirá uma descrição detalhada.

---

## 🏗️ Estrutura dos Arquivos

```
📂 smelly-phish
├── app.py
├── requirements.txt
├── .env
├── Tools/
│   ├── KnownSitesCheck.py
│   ├── BasicHeuristicsCheck.py
│   ├── AdvancedHeuristicsCheck.py
│   └── ReputationOAuthCheck.py
```

---

## 📜 Licença

Este projeto é de uso educacional, acadêmico ou privado. Para uso comercial, entre em contato com os desenvolvedores.
