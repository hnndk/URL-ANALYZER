🔎 Analisador de URLs Suspeitas

Este projeto é um script em Python que analisa URLs e tenta identificar possíveis fraudes ou ameaças de phishing e malware.

O código aplica várias regras de deteção, como:

Verificação se o host é um endereço IP.

Presença do caractere "@" na URL.

Portas não padrão (diferentes de 80 e 443).

TLDs suspeitos (ex.: .xyz, .ru, .top).

URLs muito longas ou com muitos subdomínios/hífens.

Presença de palavras-chave suspeitas (ex.: login, secure, password).

As URLs são analisadas, recebem um score de risco e são classificadas como:

✅ OK (baixo risco)

⚠️ SUSPEITA (risco elevado)

Os resultados podem ser guardados em JSON para análise posterior.

📂 Nota sobre urls.txt:
No diretório do script Python deve existir um ficheiro chamado urls.txt, que contém as URLs a analisar (uma por linha).
Exemplo de urls.txt:

http://example.com/login
https://secure-update-account.ru
http://192.168.0.10/admin
https://mybank-secure-verify-update.com/login
http://free-prizes.xyz/winner
https://normal-safe-site.com


🔎 Suspicious URL Analyzer

This project is a Python script that analyzes URLs and attempts to detect possible phishing and malware threats.

The code applies multiple detection rules, including:

Checking if the host is an IP address.

Presence of the "@" character in the URL.

Non-standard ports (other than 80 or 443).

Suspicious TLDs (e.g., .xyz, .ru, .top).

Very long URLs or hosts with too many subdomains/hyphens.

Presence of suspicious keywords (e.g., login, secure, password).

Each URL is analyzed, given a risk score, and classified as:

✅ OK (low risk)

⚠️ SUSPICIOUS (high risk)

Results can be exported to JSON for further analysis.

📂 Note about urls.txt:
In the Python script directory, there must be a file named urls.txt, containing the URLs to be analyzed (one per line).
Example of urls.txt:

http://example.com/login
https://secure-update-account.ru
http://192.168.0.10/admin
https://mybank-secure-verify-update.com/login
http://free-prizes.xyz/winner
https://normal-safe-site.com
