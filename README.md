# bruteforce-detector

Detector de brute force para logs de autenticação do SSH, escrito em Python, só com a biblioteca padrão. Ele agrupa as falhas de login por IP, identifica rajadas de tentativas e dá o alerta mais importante de todos: **um login aceito logo depois de várias falhas**, o sinal de que o ataque pode ter funcionado.

## O que ele detecta

| Regra | O que procura | Severidade |
|---|---|---|
| Brute force | N falhas do mesmo IP dentro de uma janela de T segundos | Alerta |
| Acesso após falhas | Login aceito de um IP que falhou várias vezes pouco antes | **Crítico** |

Padrões: 5 falhas em 60 segundos, e 2 ou mais falhas nos 300 segundos anteriores a um login aceito. Tudo é configurável por linha de comando.

## Requisitos

- Python 3.8 ou superior
- Nenhuma dependência externa

## Uso

```bash
python detector.py CAMINHO_DO_LOG [opções]
```

Exemplos:

```bash
python detector.py amostra-auth.log
python detector.py /var/log/auth.log --limite 10 --janela 120
python detector.py auth.log --ano 2025
```

| Opção | Descrição | Padrão |
|---|---|---|
| `--limite` | Falhas do mesmo IP para gerar alerta | 5 |
| `--janela` | Janela, em segundos, para contar as falhas | 60 |
| `--minimo-sucesso` | Falhas antes de um login aceito para alertar | 2 |
| `--janela-sucesso` | Janela, em segundos, da regra do login aceito | 300 |
| `--ano` | Ano do log (o syslog não registra) | ano atual |

Onde ficam os logs: `/var/log/auth.log` em Debian e Ubuntu, `/var/log/secure` em RHEL, CentOS e Fedora.

## Exemplo de saída

```
12 eventos analisados (9 falhas)
Regra 1: 5 falhas em 60s do mesmo IP
Regra 2: login aceito após 2+ falhas do mesmo IP em 300s

ALERTA: possível brute force
  IP: 203.0.113.45
  Falhas: 6 (maior rajada: 6 em 60s)
  Usuários testados: admin, oracle, root, test, ubuntu
  Período: 20:16:10 a 20:16:15

ALERTA CRÍTICO: login aceito após falhas
  IP: 203.0.113.99
  Usuário: root
  Horário: 20:18:04
  Falhas anteriores: 2
  Ação sugerida: tratar a conta como comprometida, trocar credenciais e investigar
```

O arquivo [`amostra-auth.log`](amostra-auth.log) é **fictício** e usa IPs de faixas reservadas para documentação (`203.0.113.0/24` e `198.51.100.0/24`). Ele reproduz três cenários: um usuário que errou a senha uma vez e acertou (normal), um ataque em rajada e um ataque que teve sucesso.

## Código de saída

Para uso em scripts e automações:

| Código | Significado |
|---|---|
| `0` | Nenhuma atividade suspeita |
| `1` | Pelo menos um alerta |
| `2` | Arquivo não encontrado |

## Como funciona

1. Uma expressão regular extrai de cada linha do `sshd` o horário, o resultado (`Failed` ou `Accepted`), o usuário e o IP.
2. As falhas são agrupadas por IP.
3. Para cada IP, uma **janela deslizante** com dois ponteiros encontra a maior quantidade de falhas dentro de T segundos. Se ela atinge o limite, há alerta.
4. Para cada login aceito, o programa conta as falhas do mesmo IP nos segundos anteriores. Se há falhas suficientes, o alerta é crítico.

## Limitações

- **Ataque lento passa despercebido.** Quem tenta uma senha a cada minuto nunca enche a janela. Aumentar `--janela` ajuda, ao custo de mais falsos positivos.
- **Só entende o formato do OpenSSH em syslog.** Outros serviços (web, FTP, banco) não são analisados.
- **O syslog não tem ano.** Logs que cruzam a virada do ano precisam do `--ano` correto.
- **Falsos positivos com NAT.** Vários usuários legítimos atrás do mesmo IP (escritório, universidade) podem somar falhas e disparar alerta.
- **É uma ferramenta de apoio, não um SIEM.** Ela não bloqueia IPs nem monitora em tempo real: analisa um arquivo de cada vez.

## Uso responsável e privacidade

- Analise apenas logs de sistemas **seus ou com autorização** de quem os administra.
- Logs de autenticação contêm **IPs e nomes de usuário**, que podem ser dados pessoais. Proteja o arquivo, defina prazo de retenção e não o suba para repositórios públicos (por isso o `.gitignore` bloqueia `*.log`).
- Para o contexto de LGPD, veja o guia [lgpd-checklist-tecnico](https://github.com/joaodipauladev/lgpd-checklist-tecnico), em especial os capítulos de [logs e monitoramento](https://github.com/joaodipauladev/lgpd-checklist-tecnico/blob/main/docs/04-logs-e-monitoramento.md) e de [resposta a incidentes](https://github.com/joaodipauladev/lgpd-checklist-tecnico/blob/main/docs/06-resposta-a-incidentes.md).

## Roadmap

- [ ] Saída em JSON para integração com outras ferramentas
- [ ] Lista de IPs confiáveis (allowlist)
- [ ] Leitura de logs de servidores web (tentativas de login em painéis)
- [ ] Leitura da entrada padrão, para uso com `tail` e `journalctl`
- [ ] Testes automatizados
- [ ] Alerta por e-mail

## Licença

MIT. Veja o arquivo [LICENSE](LICENSE).

Feito por João ([@joaodipauladev](https://github.com/joaodipauladev)).