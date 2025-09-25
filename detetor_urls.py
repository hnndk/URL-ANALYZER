import re  # regex para validar endereços IP e fazer verificações de URLs em strings
from urllib.parse import urlparse  # para analisar URLs e extrair componentes como domínio, caminho, etc.
import json  # para guardar resultados em formato JSON

# Definição de parâmetros da deteção
LIMIAR = 3  # número mínimo de +pntos de reisco para classificar como suspeito
TLD_SUSPEITOS = {"xyz", "top", "club", "ru", "tk", "click", "zip", "win"}  # domínios de topo suspeitos
PALAVRAS_CHAVE = [
    "phishing", "fraude", "golpe", "scam", "malware", "ransomware", "trojan", "spyware",
    "keylogger", "sequestro", "vazamento", "vazou", "comprometido", "comprometida",
    "senha", "trocar senha", "atualizar conta", "verificar conta", "confirme", "confirmar",
    "confirmação", "pagar", "pagamento", "boleto", "fatura", "comprovante", "recibo",
    "reembolso", "prêmio", "premio", "sorteio", "vencedor", "urgente", "urgência",
    "atenção", "alerta", "bloqueado", "bloqueio", "suspenso", "suspensão", "limite",
    "documento", "identidade", "cpf", "cartão", "cartao", "cvv", "nº do cartão", "numero do cartao",
    "baixar", "download", "instalar", "executar", "acesse", "clique aqui", "clicar", "anexo",
    "anexo malicioso", "token", "autenticar", "autenticação", "2fa", "otp", "senha única",
    "compartilhe", "compartilhar", "recuperar conta", "desbloquear", "atualização de segurança",
    "credential", "credentials", "login", "password", "verify", "verification", "update",
    "urgent", "alert", "suspicious", "click here", "invoice", "receipt",
    "payment", "wire transfer", "bank transfer", "refund", "prize", "winner", "lottery",
    "account suspended", "account locked", "confirm your account", "security alert",
    "compromised", "data breach", "leaked", "secure your account", "two-factor",
    "one-time", "credential stuffing", "exploit", "payload", "drive-by", "attached",
    "attachment", "open attachment", "execute", "install", "update required", "verify now",
    "urgent action required", "social engineering", "support team", "billing", "invoice attached",
    # extensões e domínios suspeitos
    ".exe", ".zip", ".scr", ".js", ".vbs", ".bat", ".docm", ".rtf",
    ".php", ".cgi", ".phtml", ".hta",
    ".xyz", ".top", ".info", ".ru", ".cn"]


def eh_ip(host: str) -> bool:
    """
    Verifica se o host é um endereço IP válido.
    Usa regex para garantir que tem o formato X.X.X.X onde cada X tem 1-3 dígitos
    """
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))  # verifica o formato do IP


def analisar_url(url: str):
    """
    Receber uma URL, aplica regras para detectar se é suspeita e devolve:
    - score: número de sinais encontrados
    - sinais: lista dos motivos de suspeita
    - estado: 'SUSPEITA' ou 'OK'
    """

    url = url.strip()  # remove espaços em branco
    if not url:  # se a URL estiver vazia
        return None

    # Decompor a URL em partes
    p = urlparse(url)  # analisa a URL
    host = p.hostname or ""  # extrai o host (domínio)
    porta = p.port  # extrai a porta, se houver
    caminho = p.path or ""  # extrai o caminho
    query = p.query or ""  # extrai a query string

    score = 0  # inicializa o score
    sinais = []  # inicializa a lista de sinais

    # 1) Host é um endereço IP
    if eh_ip(host):
        score += 1
        sinais.append("Host is an IP address")

    # 2) @ na URL (padrão típico em ataque pishing)
    if "@" in url:
        score += 1
        sinais.append("Contains '@' in URL")

    # 3) Porta não padrão (80 para HTTP, 443 para HTTPS)
    if porta and porta not in {80, 443}:
        score += 1
        sinais.append(f"Non-standard port: {porta}")

    # 4) TLD suspeito
    tld = host.split(".")[-1] if host else ""  # extrai a TLD do host
    if tld in TLD_SUSPEITOS:
        score += 1
        sinais.append(f"Suspicious TLD: .{tld}")

    # 5) Muitos pontos no host (ex.: subdomínios encadeados em pishing)
    if host.count(".") >= 3:
        score += 1
        sinais.append("Too many dots in host")

    # 6) URL muito longa (mais de 75 caracteres)
    if len(url) > 75:
        score += 1
        sinais.append("Very long URL")

    # 7) Muitos hífens no host (ex.: login-secure-verify-update.com)
    if host.count("-") >= 3:
        score += 1
        sinais.append("Too many hyphens in host")

    # 8) Palavras-chave de pishing (ex.: login, secure, verify
    texto = (host + caminho + query).lower()  # combina partes relevantes e converte para minúsculas
    if any(pal in texto for pal in PALAVRAS_CHAVE):
        score += 1
        sinais.append("Contains suspicious keywords")

    # Classificação final
    estado = "SUSPEITA" if score >= LIMIAR else "OK"
    return {"url": url, "score": score, "sinais": sinais, "estado": estado}


# Função main
def main():
    resultados = []

    # 1) Ler URLs do arquivo
    with open("urls.txt", encoding="utf-8") as f:
        for linha in f:
            r = analisar_url(linha)  # analisar cada URL
            if r:
                resultados.append(r)  # armazenar o resultado

    # 2) Filtras apenas as URLs suspeitas
    suspeitas = [r for r in resultados if r["estado"] == "SUSPEITA"]

    # 3) Ordenar por score decrescente
    suspeitas.sort(key=lambda x: x["score"], reverse=True)  # ordenar por score decrescente

    # 4) Gustar em JSON para análise posterior
    with open("urls_suspeitas.json", "w", encoding="utf-8") as out:
        json.dump(suspeitas, out, indent=2,
                  ensure_ascii=False)  # guardar em JSON, indent para legibilidade e ensure_ascii para suportar caracteres especiais

    # %) Mostrar resumo
    print(f"Total URLs analisadas: {len(resultados)} | Suspeitas: {len(suspeitas)}")
    for r in suspeitas[:5]:  # mostrar as 5 mais suspeitas
        print(f"Score: {r['score']} | URL: {r['url']} | Sinais: {', '.join(r['sinais'])}")


if __name__ == "__main__":
    main()
