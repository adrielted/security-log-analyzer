import re

contagem = {}
with open("auth.log") as arquivo:
    for linha in arquivo:
        resultado = re.search(r"(Failed|Accepted)", linha).group(1)
        ip = re.search(r"\d+\.\d+\.\d+\.\d+", linha).group()
        usuario = re.search(r"(\S+) from", linha).group(1) 
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
