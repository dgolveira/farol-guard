<p align="center">
  <img src="internal/server/web/icon.svg" width="72" height="72" alt="farol-guard">
</p>

<h1 align="center">farol-guard</h1>

<p align="center">
  Auditor de servidores Linux via SSH, sem agente (Debian, Ubuntu, família
  RHEL, Fedora, Amazon Linux, Arch e derivados): usuários, chaves, sshd,
  atualizações, CVEs e recursos, com dashboard local e rotação segura de chaves
  SSH.
</p>

<p align="center">
  <a href="https://github.com/dgolveira/farol-guard/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/dgolveira/farol-guard/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/dgolveira/farol-guard/actions/workflows/codeql.yml"><img alt="CodeQL" src="https://github.com/dgolveira/farol-guard/actions/workflows/codeql.yml/badge.svg"></a>
  <a href="https://github.com/dgolveira/farol-guard/releases"><img alt="Release" src="https://img.shields.io/github/v/release/dgolveira/farol-guard?sort=semver"></a>
  <a href="https://goreportcard.com/report/github.com/dgolveira/farol-guard"><img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/dgolveira/farol-guard"></a>
  <a href="LICENSE"><img alt="Licença: MIT" src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
</p>

<p align="center">
  <a href="README.md">English</a> | <b>Português (Brasil)</b>
</p>

---

<p align="center"><img src="docs/images/fleet.png" alt="Visão da frota" width="900"></p>

O farol-guard vigia uma frota de servidores Linux por fora: conecta por SSH,
roda um coletor somente leitura e mostra quem pode entrar, com quais chaves, o
que está desatualizado ou vulnerável e o que está perto de ficar sem disco, sem
instalar nada nos servidores.

## Destaques

- **Sem agente e só com chave pública.** Uma sessão SSH por host, coletor
  somente leitura via `bash -s` e `sudo -n` quando você não entra como root.
  Nenhum daemon, nenhuma porta aberta, nenhum login por senha.
- **Auditoria de acesso.** Usuários, contas com UID 0, sudoers e `NOPASSWD`,
  cada linha do `authorized_keys` com fingerprint, configuração efetiva do
  `sshd -T`, logins SSH agrupados por IP de origem e por chave.
- **Atualizações e CVEs.** Atualizações pendentes e de segurança (`apt`, `dnf`,
  `pacman`), fim do suporte da versão, reboot pendente e CVEs com a versão
  corrigida e o comando exato de atualização, vindas da [OSV.dev](https://osv.dev)
  (Debian, Ubuntu e derivados), dos avisos de segurança do `dnf` do próprio host
  (família RHEL, Fedora, Amazon Linux) e do tracker de segurança do Arch Linux.
- **Saúde.** Discos e inodes, memória, swap, load, CPU, erros de interface de
  rede e de kernel, units do systemd com falha, portas abertas, firewall,
  fail2ban, NTP, containers e snaps.
- **Gestão segura de chaves.** Instalar, rotacionar e remover chaves com
  simulação, backup, verificação de login e rollback automático. Uma chave
  dedicada do app gerada com entropia do kernel, criptografada com senha
  guardada no chaveiro do sistema, instalada com `restrict` e opcionalmente
  `from=`.
- **Dashboard e relatórios.** Interface web local (inglês e português, temas
  claro e escuro), log de atividade ao vivo, editor de inventário com grupos e
  filtros, histórico e relatórios HTML, JSON e Markdown.
- **Fácil de distribuir.** Um binário Go estático, pacotes `.deb` para amd64 e
  arm64, imagem de container distroless e exemplos para Docker Compose e
  Kubernetes.

## Telas

| Detalhes do host | Inventário |
| --- | --- |
| <img src="docs/images/host.png" alt="Detalhes do host" width="440"> | <img src="docs/images/inventory.png" alt="Inventário" width="440"> |

| Gestão de chaves | Relatório HTML |
| --- | --- |
| <img src="docs/images/keys.png" alt="Gestão de chaves" width="440"> | <img src="docs/images/report-modal.png" alt="Relatório HTML" width="440"> |

## Como funciona

O farol-guard nunca guarda senhas de SSH e não aceita login por senha: **toda
conexão usa chave SSH**. Antes da primeira verificação, uma chave pública já
precisa estar autorizada em cada servidor, para o `root` ou para um usuário com
`sudo` sem senha. Você pode usar a chave que já tem, ou seguir os
[primeiros passos](docs/getting-started.md#path-b-prepare-the-access-manually)
para criar manualmente um usuário dedicado e restrito e a chave do app.

## Instalação

**Repositórios assinados** para apt, dnf, zypper e pacman, com os comandos de
configuração de cada distribuição: <https://dgolveira.github.io/farol-guard/>.

**Pacotes** (nas [releases](https://github.com/dgolveira/farol-guard/releases), amd64 e arm64):

```bash
sudo apt install ./farol-guard_1.1.0_amd64.deb                 # Debian, Ubuntu, Mint, Pop!_OS...
sudo dnf install ./farol-guard-1.1.0-1.x86_64.rpm              # Fedora, RHEL, Rocky, Alma, Oracle, Amazon Linux
sudo zypper install --allow-unsigned-rpm ./farol-guard-1.1.0-1.x86_64.rpm   # openSUSE
sudo pacman -U ./farol-guard-1.1.0-1-x86_64.pkg.tar.zst        # Arch, Manjaro, EndeavourOS
farol version
```

Cada pacote instala o binário `farol`, o ícone **farol-guard** no menu de
aplicativos (inicia o dashboard em segundo plano e abre o navegador; com o
botão direito há "Parar o dashboard") e units de usuário do systemd para a
verificação diária e para o dashboard (desabilitadas por padrão).

**Imagem de container** ([GitHub Container Registry](https://github.com/dgolveira/farol-guard/pkgs/container/farol-guard), amd64 e arm64):

```bash
docker run --rm ghcr.io/dgolveira/farol-guard:1.1.0 version
```

**A partir do código, em qualquer distribuição** (Go e make; se o Go da
distribuição for antigo, o Go 1.26 é baixado automaticamente):

```bash
sudo dnf install golang make git        # ou: apt install golang-go make git / pacman -S go make git / zypper in go make git
git clone https://github.com/dgolveira/farol-guard.git
cd farol-guard
make build-local                        # gera dist/farol
sudo make install                       # /usr/local: binário, ícone no menu, units de usuário do systemd
```

Só com Docker: `make build` (binário) e `make packages` (pacotes `.deb`, `.rpm`
e do Arch para amd64 e arm64). Veja as [plataformas suportadas](docs/platforms.md).

## Uso rápido

```bash
farol init                                   # inventário de exemplo em ~/.config/farol-guard
$EDITOR ~/.config/farol-guard/inventory.yaml # cadastre seus hosts
farol check -o relatorio.html                # audita e gera o relatório
farol open                                   # inicia o dashboard e abre o navegador
```

Flags úteis do `farol check`: `-g grupo`, `-H host`, `--refresh` (atualiza
antes os metadados de pacotes: `apt-get update`, `dnf makecache`), `--no-cve`,
`--fail-on high` (código de saída 3 para cron ou CI), `-v` (log passo a passo),
`-f json|md|html`, `--lang en|pt-BR`.

## Modelo de segurança

O código é público, então nada nele ajuda um atacante. Chaves e segredos são
gerados na hora, com o gerador criptográfico do kernel, em cada instalação; não
existem chaves padrão ou embutidas; e a chave do app é protegida pelo chaveiro
do sistema, por `restrict` e opcionalmente por `from=`. O dashboard escuta em
`127.0.0.1` com token de sessão, checagem do cabeçalho Host e proteção contra
CSRF.

**O que sai da sua máquina:** apenas nomes e versões de pacotes, enviados para
`api.osv.dev` na consulta de CVEs dos hosts Debian e Ubuntu. Para hosts Arch, a
lista pública de avisos é baixada de `security.archlinux.org` e comparada
localmente, sem enviar nada. Hosts da família RHEL usam os próprios
repositórios. Nenhum hostname, IP ou usuário sai da sua máquina. Use `--no-cve`
(ou a opção no dashboard) para pular a consulta.

## Documentação

A documentação detalhada está em inglês:

- [Primeiros passos](docs/getting-started.md): modelo de acesso, primeiro acesso, inventário
- [Plataformas suportadas](docs/platforms.md): distribuições auditadas, fontes de CVE, pacotes do cliente
- [Chaves SSH e modelo de segurança](docs/keys.md)
- [Hospedagem](docs/hosting.md): túnel SSH, Docker com Caddy, Kubernetes com oauth2-proxy
- [Desenvolvimento](docs/development.md): build, laboratório de testes, estrutura

## Perguntas frequentes

**Preciso instalar algo nos servidores?**
Não. Basta acesso SSH com chave e `sudo -n` (ou root) para a auditoria completa.

**Ele altera algo nos servidores?**
As verificações são somente leitura. A única escrita opcional é a atualização
dos metadados de pacotes (`apt-get update`, `dnf makecache`) quando você marca
"Atualizar listas de pacotes". As operações
de chave alteram o `authorized_keys`, sempre com simulação, backup e
verificação.

**Quais distribuições são suportadas?**
Debian, Ubuntu e derivados (Linux Mint, Pop!_OS, Zorin, elementary, Raspberry
Pi OS), a família RHEL (RHEL, CentOS Stream, Rocky, AlmaLinux, Oracle Linux),
Fedora, Amazon Linux, openSUSE Leap, Tumbleweed e SLES, e a família Arch
(Arch, Manjaro, EndeavourOS). Outras
distribuições são coletadas parcialmente, sem avaliação de atualizações e CVEs.
Detalhes em [plataformas suportadas](docs/platforms.md).

**Funciona no WSL?**
Sim, no Ubuntu ou Debian do WSL2. O `farol open` (e o ícone no menu, com WSLg)
detecta o WSL e abre o dashboard no Microsoft Edge do Windows como janela de
aplicativo, ou no navegador padrão do Windows se o Edge não estiver disponível;
o dashboard para 20 segundos depois que a janela fecha. O WSL normalmente não
tem o chaveiro do GNOME, então informe a senha da chave do app em
`FAROL_GUARD_APP_PASSPHRASE`, e habilite `systemd=true` no `/etc/wsl.conf` para
usar as units do systemd.

**Meu servidor me bloqueou depois de algumas verificações.**
Ferramentas como sshguard e fail2ban contam handshakes interrompidos. O
farol-guard abre no máximo uma conexão interrompida por host novo (para
capturar a chave do host) e pula hosts cuja chave ainda aguarda revisão.

**Existe tela de login para hospedar?**
Não embutida. Coloque um proxy com autenticação na frente, veja
[hospedagem](docs/hosting.md). Contribuições são bem-vindas.

## Contribuindo

Issues e pull requests são bem-vindos. Leia o [CONTRIBUTING.md](CONTRIBUTING.md)
e o [Código de Conduta](CODE_OF_CONDUCT.md). Vulnerabilidades devem ser
reportadas de forma privada, como descrito no [SECURITY.md](SECURITY.md).

## Licença

[MIT](LICENSE). Componentes de terceiros estão em
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
