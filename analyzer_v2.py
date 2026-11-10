import re
import sys

if len(sys.argv) < 2:
    sys.exit("Uso: python3 analyzer_v2.py <arquivo_de_log>")

contagem = {}
ignoradas = 0
eventos = 0

with open(sys.argv[1]) as arquivo:
    for linha in arquivo:
        busca = re.search(r"(Failed|Accepted)", linha)
        if busca is None:
            ignoradas += 1
            continue
        resultado = busca.group(1)
    
        ip = re.search(r"\d+\.\d+\.\d+\.\d+", linha).group()
        usuario = re.search(r"(\S+) from", linha).group(1) 
        eventos += 1
        if resultado == "Failed":
            if ip in contagem:
                contagem[ip] += 1
            else:
                contagem[ip] = 1
        else:
            if ip in contagem:
                print(f"[ALERTA] Login com sucesso de {usuario} vindo de {ip}, que já tinha falhado antes")

limite = 3
for ip, total in contagem.items():
        if total >= limite:
            print(f"[ALERTA] Possível brute force de {ip} ({total} falhas)")

print(f"Eventos:{eventos} Ignoradas:{ignoradas}")