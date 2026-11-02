import argparse
import re
import sys
from collections import defaultdict
from datetime import datetime

PADRAO_EVENTO = re.compile(
    r"^(?P<mes>\w{3})\s+(?P<dia>\d+)\s+(?P<hora>[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+"
    r"(?P<resultado>Failed|Accepted) \w+ for (?:invalid user )?(?P<usuario>\S+) from (?P<ip>\S+)"
)


def converter_horario(evento, ano):
    texto = f"{ano} {evento['mes']} {evento['dia']} {evento['hora']}"
    return datetime.strptime(texto, "%Y %b %d %H:%M:%S")


def ler_eventos(caminho, ano):
    eventos = []
    with open(caminho, encoding="utf-8", errors="replace") as arquivo:
        for linha in arquivo:
            correspondencia = PADRAO_EVENTO.match(linha)
            if correspondencia:
                evento = correspondencia.groupdict()
                evento["horario"] = converter_horario(evento, ano)
                eventos.append(evento)
    return sorted(eventos, key=lambda e: e["horario"])


def agrupar_por_ip(falhas):
    por_ip = defaultdict(list)
    for falha in falhas:
        por_ip[falha["ip"]].append(falha)
    return por_ip


def maior_rajada(horarios, janela):
    horarios = sorted(horarios)
    maior = 0
    inicio = 0
    for fim in range(len(horarios)):
        while (horarios[fim] - horarios[inicio]).total_seconds() > janela:
            inicio += 1
        maior = max(maior, fim - inicio + 1)
    return maior


def detectar_brute_force(falhas, limite, janela):
    alertas = []
    for ip, lista in agrupar_por_ip(falhas).items():
        horarios = [f["horario"] for f in lista]
        rajada = maior_rajada(horarios, janela)
        if rajada >= limite:
            alertas.append({
                "ip": ip,
                "total": len(lista),
                "rajada": rajada,
                "usuarios": sorted({f["usuario"] for f in lista}),
                "primeira": min(horarios),
                "ultima": max(horarios),
            })
    return alertas


def detectar_acesso_apos_falhas(eventos, minimo, janela):
    alertas = []
    for posicao, evento in enumerate(eventos):
        if evento["resultado"] != "Accepted":
            continue
        falhas_antes = [
            e for e in eventos[:posicao]
            if e["resultado"] == "Failed"
            and e["ip"] == evento["ip"]
            and 0 <= (evento["horario"] - e["horario"]).total_seconds() <= janela
        ]
        if len(falhas_antes) >= minimo:
            alertas.append({
                "ip": evento["ip"],
                "usuario": evento["usuario"],
                "horario": evento["horario"],
                "falhas_antes": len(falhas_antes),
            })
    return alertas


def ler_argumentos():
    parser = argparse.ArgumentParser(
        description="Detecta brute force em logs de autenticação do SSH."
    )
    parser.add_argument("caminho", help="arquivo de log (ex.: /var/log/auth.log)")
    parser.add_argument("--limite", type=int, default=5,
                        help="falhas do mesmo IP para gerar alerta (padrão: 5)")
    parser.add_argument("--janela", type=int, default=60,
                        help="janela em segundos para contar as falhas (padrão: 60)")
    parser.add_argument("--minimo-sucesso", type=int, default=2,
                        help="falhas antes de um login aceito para alertar (padrão: 2)")
    parser.add_argument("--janela-sucesso", type=int, default=300,
                        help="janela em segundos para a regra do login aceito (padrão: 300)")
    parser.add_argument("--ano", type=int, default=datetime.now().year,
                        help="ano do log, já que o syslog não registra (padrão: ano atual)")
    return parser.parse_args()


def main():
    args = ler_argumentos()

    try:
        eventos = ler_eventos(args.caminho, args.ano)
    except FileNotFoundError:
        print(f"Arquivo não encontrado: {args.caminho}")
        sys.exit(2)

    falhas = [e for e in eventos if e["resultado"] == "Failed"]

    print(f"{len(eventos)} eventos analisados ({len(falhas)} falhas)")
    print(f"Regra 1: {args.limite} falhas em {args.janela}s do mesmo IP")
    print(f"Regra 2: login aceito após {args.minimo_sucesso}+ falhas do mesmo IP em {args.janela_sucesso}s")
    print()

    brute = detectar_brute_force(falhas, args.limite, args.janela)
    acessos = detectar_acesso_apos_falhas(eventos, args.minimo_sucesso, args.janela_sucesso)

    if not brute and not acessos:
        print("Nenhuma atividade suspeita detectada.")
        sys.exit(0)

    for a in brute:
        print("ALERTA: possível brute force")
        print(f"  IP: {a['ip']}")
        print(f"  Falhas: {a['total']} (maior rajada: {a['rajada']} em {args.janela}s)")
        print(f"  Usuários testados: {', '.join(a['usuarios'])}")
        print(f"  Período: {a['primeira'].strftime('%H:%M:%S')} a {a['ultima'].strftime('%H:%M:%S')}")
        print()

    for a in acessos:
        print("ALERTA CRÍTICO: login aceito após falhas")
        print(f"  IP: {a['ip']}")
        print(f"  Usuário: {a['usuario']}")
        print(f"  Horário: {a['horario'].strftime('%H:%M:%S')}")
        print(f"  Falhas anteriores: {a['falhas_antes']}")
        print("  Ação sugerida: tratar a conta como comprometida, trocar credenciais e investigar")
        print()

    sys.exit(1)


if __name__ == "__main__":
    main()