# Incident Response Toolkit

Ferramenta de triage forense para resposta a incidentes em Windows. Coleta automaticamente evidências do sistema no momento do incidente e gera relatório HTML + pacote ZIP de evidências.

![Python](https://img.shields.io/badge/Python-3776AB?style=flat&logo=python&logoColor=white)
![Security](https://img.shields.io/badge/Incident_Response-Critical-ef4444?style=flat&logo=shield&logoColor=white)
![Forensics](https://img.shields.io/badge/Digital_Forensics-ef4444?style=flat&logo=target&logoColor=white)

## O que coleta

| Artefato | Descrição |
|----------|-----------|
| **Processos** | Todos os processos ativos com CPU, caminho e empresa |
| **Conexões TCP** | Todas as conexões estabelecidas e em escuta com PID |
| **Autorun** | Entradas de persistência no registro do Windows |
| **Eventos** | Eventos de segurança dos últimos 60 minutos |
| **Arquivos** | Arquivos modificados recentemente em locais sensíveis |
| **Sessões** | Usuários atualmente logados no sistema |

## Saída

```
ir_output/
├── ir_SERVIDOR01_20260423_143022.html   ← relatório visual
├── ir_SERVIDOR01_20260423_143022.json   ← dados estruturados
└── ir_SERVIDOR01_20260423_143022.zip    ← pacote de evidências
```

## Uso

```bash
# IMPORTANTE: Execute como Administrador
python ir_collector.py
```

## Workflow de Resposta

1. Execute `ir_collector.py` imediatamente ao detectar incidente
2. Preserve o `.zip` gerado como evidência
3. Analise o `.html` para identificar IOCs
4. Correlacione processos suspeitos com conexões TCP
5. Verifique autoruns para persistência maliciosa

## Requisitos

- Python 3.8+
- Windows Server 2016+ / Windows 10+
- Permissões de Administrador
