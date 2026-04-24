"""
Incident Response Toolkit — coleta forense inicial e triage automatizado.
Captura estado do sistema no momento do incidente: processos, conexões,
usuários logados, eventos recentes e arquivos modificados recentemente.
"""

import subprocess
import json
import os
import sys
import hashlib
import zipfile
from datetime import datetime, timedelta
from pathlib import Path


SAIDA_BASE   = Path(os.path.dirname(os.path.abspath(__file__))) / "ir_output"
MINUTOS_ATRAS = 60   # janela de tempo para eventos e arquivos


def _ps(script: str, timeout: int = 30) -> dict | list | None:
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True, text=True, timeout=timeout
        )
        raw = r.stdout.strip()
        return json.loads(raw) if raw else None
    except Exception:
        return None


def _cmd(args: list, timeout: int = 15) -> str:
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ""


# ── Coleta de artefatos ────────────────────────────────────────────────────────

def coletar_processos() -> list:
    dados = _ps("""
Get-Process | Select-Object Id, Name, CPU, WorkingSet, Path, Company,
    @{N='StartTime';E={if($_.StartTime){$_.StartTime.ToString('yyyy-MM-dd HH:mm:ss')}else{''}}} |
    Sort-Object CPU -Descending | ConvertTo-Json -Depth 2""")
    return dados if isinstance(dados, list) else ([dados] if dados else [])


def coletar_conexoes() -> list:
    dados = _ps("""
$conns = Get-NetTCPConnection -State Established,Listen -ErrorAction SilentlyContinue |
    ForEach-Object {
        $proc = try { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name } catch { 'N/A' }
        [PSCustomObject]@{
            local_addr  = $_.LocalAddress
            local_port  = $_.LocalPort
            remote_addr = $_.RemoteAddress
            remote_port = $_.RemotePort
            estado      = $_.State
            pid         = $_.OwningProcess
            processo    = $proc
        }
    }
$conns | ConvertTo-Json -Depth 2""")
    return dados if isinstance(dados, list) else ([dados] if dados else [])


def coletar_usuarios_logados() -> list:
    saida = _cmd(["query", "session"])
    linhas = []
    for linha in (saida or "").splitlines()[1:]:
        partes = linha.split()
        if len(partes) >= 2:
            linhas.append({"sessao": linha.strip()})
    return linhas


def coletar_autorun() -> list:
    dados = _ps("""
$paths = @(
    'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
    'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
    'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'
)
$result = foreach ($p in $paths) {
    $key = Get-ItemProperty $p -ErrorAction SilentlyContinue
    if ($key) {
        $key.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
            [PSCustomObject]@{ chave = $p; nome = $_.Name; valor = $_.Value }
        }
    }
}
$result | ConvertTo-Json -Depth 2""")
    return dados if isinstance(dados, list) else ([dados] if dados else [])


def coletar_eventos_recentes(minutos: int) -> list:
    inicio = (datetime.now() - timedelta(minutes=minutos)).strftime("%Y-%m-%dT%H:%M:%S")
    dados = _ps(f"""
$ev = Get-WinEvent -FilterHashtable @{{
    LogName='Security'; Id=@(4624,4625,4648,4688,4720,4726,4740);
    StartTime=[datetime]::Parse('{inicio}')
}} -MaxEvents 200 -ErrorAction SilentlyContinue
if (-not $ev) {{ Write-Output '[]'; exit }}
$ev | Select-Object Id, TimeCreated, Message |
    ForEach-Object {{ [PSCustomObject]@{{
        id    = $_.Id
        tempo = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
        msg   = ($_.Message -split "`n")[0]
    }} }} | ConvertTo-Json -Depth 2""")
    return dados if isinstance(dados, list) else ([dados] if dados else [])


def coletar_arquivos_modificados(minutos: int) -> list:
    inicio = (datetime.now() - timedelta(minutes=minutos))
    alvos  = [
        os.environ.get("TEMP", "C:\\Windows\\Temp"),
        "C:\\Windows\\System32",
        os.path.expanduser("~\\Downloads"),
        os.path.expanduser("~\\Desktop"),
    ]
    encontrados = []
    for pasta in alvos:
        if not os.path.exists(pasta):
            continue
        try:
            for arq in Path(pasta).rglob("*"):
                if arq.is_file():
                    mtime = datetime.fromtimestamp(arq.stat().st_mtime)
                    if mtime >= inicio:
                        encontrados.append({
                            "caminho": str(arq),
                            "tamanho": arq.stat().st_size,
                            "modificado": mtime.strftime("%Y-%m-%d %H:%M:%S"),
                        })
        except PermissionError:
            pass
    return sorted(encontrados, key=lambda x: x["modificado"], reverse=True)[:50]


def hash_arquivo(caminho: str) -> str:
    try:
        h = hashlib.sha256()
        with open(caminho, "rb") as f:
            for bloco in iter(lambda: f.read(65536), b""):
                h.update(bloco)
        return h.hexdigest()
    except Exception:
        return "N/A"


# ── Relatório ─────────────────────────────────────────────────────────────────

def gerar_relatorio(artefatos: dict, gerado_em: str) -> str:
    hostname = artefatos.get("hostname", "servidor")

    def secao(titulo: str, dados: list, campos: list) -> str:
        if not dados:
            return f"<section><h3>{titulo}</h3><p class='vazio'>Sem dados.</p></section>"
        ths = "".join(f"<th>{c}</th>" for c in campos)
        trs = ""
        for item in dados[:200]:
            vals = [str(item.get(c, "—"))[:80] for c in campos]
            tds  = "".join(f"<td>{v}</td>" for v in vals)
            trs += f"<tr>{tds}</tr>"
        return f"""<section>
          <h3>{titulo} <span class="cnt">({len(dados)})</span></h3>
          <div class="tw"><table><thead><tr>{ths}</tr></thead><tbody>{trs}</tbody></table></div>
        </section>"""

    return f"""<!DOCTYPE html><html lang="pt-BR">
<head><meta charset="UTF-8"><title>IR Triage — {hostname}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',sans-serif;background:#020c1b;color:#c9d1d9}}
header{{background:linear-gradient(135deg,#4a0000,#1a0a0a);border-bottom:1px solid #ef444433;
        padding:22px 32px}}
header h1{{font-size:1.4rem;color:#ef4444}}
header p{{opacity:.7;margin-top:4px;font-size:.85rem;color:#fca5a5}}
.alerta-banner{{background:#7f1d1d;border:1px solid #ef444488;border-radius:8px;
                padding:12px 20px;margin:20px;font-size:.9rem;color:#fca5a5}}
.container{{max-width:1300px;margin:0 auto;padding:16px}}
section{{background:#0a1628;border:1px solid #ef444422;border-radius:8px;
         padding:16px 20px;margin-bottom:14px}}
h3{{font-size:.8rem;text-transform:uppercase;letter-spacing:.08em;color:#ef4444;
    margin-bottom:10px;padding-bottom:6px;border-bottom:1px solid #ef444422}}
.cnt{{color:#7ecfff;font-weight:400}}
.tw{{overflow-x:auto}}
table{{width:100%;border-collapse:collapse;font-size:.76rem}}
th{{background:#1a0a0a;text-align:left;padding:7px 9px;color:#fca5a5;font-weight:500}}
td{{padding:6px 9px;border-bottom:1px solid #ffffff06;font-family:monospace}}
tr:hover td{{background:#0d1628}}tr:last-child td{{border:none}}
.vazio{{color:#484f58;font-size:.83rem;padding:8px 0}}
footer{{text-align:center;padding:16px;color:#484f58;font-size:.73rem}}
</style></head>
<body>
<header>
  <h1>⚠ Incident Response — Triage Report</h1>
  <p>Host: <strong>{hostname}</strong> &nbsp;|&nbsp; Coletado: <strong>{gerado_em}</strong>
     &nbsp;|&nbsp; Janela: últimos {MINUTOS_ATRAS} minutos</p>
</header>
<div class="alerta-banner">
  Este relatório contém dados forenses coletados automaticamente. Preserve a evidência — não modifique o sistema antes de concluir a análise.
</div>
<div class="container">
  {secao("Processos em Execução", artefatos.get("processos",[]), ["Id","Name","CPU","Path"])}
  {secao("Conexões TCP Ativas", artefatos.get("conexoes",[]), ["local_addr","local_port","remote_addr","remote_port","estado","processo"])}
  {secao("Entradas de Autorun (Registro)", artefatos.get("autorun",[]), ["chave","nome","valor"])}
  {secao("Eventos de Segurança Recentes", artefatos.get("eventos",[]), ["id","tempo","msg"])}
  {secao("Arquivos Modificados Recentemente", artefatos.get("arquivos",[]), ["caminho","tamanho","modificado"])}
  {secao("Sessões de Usuários", artefatos.get("usuarios_logados",[]), ["sessao"])}
</div>
<footer>Incident Response Toolkit · github.com/Luca-css/incident-response-toolkit · {gerado_em}</footer>
</body></html>"""


def main():
    gerado_em = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    hostname  = os.environ.get("COMPUTERNAME", "servidor")
    ts        = datetime.now().strftime("%Y%m%d_%H%M%S")
    SAIDA_BASE.mkdir(exist_ok=True)

    print(f"\n  INCIDENT RESPONSE TOOLKIT — Triage")
    print(f"  Host: {hostname} | {gerado_em}\n")
    print(f"  [!] Execute como Administrador para coleta completa.\n")

    print("  Coletando processos...")
    processos = coletar_processos()

    print("  Coletando conexões TCP...")
    conexoes = coletar_conexoes()

    print("  Coletando autoruns do registro...")
    autorun = coletar_autorun()

    print("  Coletando eventos de segurança recentes...")
    eventos = coletar_eventos_recentes(MINUTOS_ATRAS)

    print("  Coletando arquivos modificados recentemente...")
    arquivos = coletar_arquivos_modificados(MINUTOS_ATRAS)

    print("  Coletando sessões de usuários...")
    usuarios_logados = coletar_usuarios_logados()

    artefatos = {
        "hostname": hostname, "gerado_em": gerado_em,
        "processos": processos, "conexoes": conexoes,
        "autorun": autorun, "eventos": eventos,
        "arquivos": arquivos, "usuarios_logados": usuarios_logados,
    }

    # Salvar JSON
    json_path = SAIDA_BASE / f"ir_{hostname}_{ts}.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(artefatos, f, ensure_ascii=False, indent=2, default=str)

    # Salvar HTML
    html_path = SAIDA_BASE / f"ir_{hostname}_{ts}.html"
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(gerar_relatorio(artefatos, gerado_em))

    # Empacotar evidências
    zip_path = SAIDA_BASE / f"ir_{hostname}_{ts}.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(json_path, json_path.name)
        z.write(html_path, html_path.name)

    print(f"\n  Processos coletados:  {len(processos)}")
    print(f"  Conexões TCP:         {len(conexoes)}")
    print(f"  Autoruns:             {len(autorun)}")
    print(f"  Eventos recentes:     {len(eventos)}")
    print(f"  Arquivos modificados: {len(arquivos)}")
    print(f"\n  HTML:  {html_path}")
    print(f"  JSON:  {json_path}")
    print(f"  ZIP:   {zip_path}\n")

    try:
        os.startfile(str(html_path))
    except Exception:
        pass


if __name__ == "__main__":
    if sys.platform != "win32":
        print("[AVISO] Este script foi feito para Windows.")
    main()
