# Guia de estudo — Auth Log Analyzer

## A ideia

Uma aplicação recebe um arquivo com tentativas de login. Cinco falhas do mesmo IP dentro de 60 segundos geram um alerta para revisão. Você pode mudar esses dois números.

O projeto usa somente recursos que já vêm no Python: leitura de CSV, validação de IP, datas, JSON, SQLite e testes. Não precisa instalar pacotes.

## Como testar no Linux

Você pode extrair o ZIP ou clonar o repositório com `git clone https://github.com/Cat027/auth-log-analyzer.git`. Abra um terminal dentro da pasta `auth-log-analyzer`:

```bash
python3 --version
python3 logwatch.py data/sample_logins.csv --output reports/demo
```

Use Python 3.12 ou superior. O exemplo deve mostrar 12 eventos válidos, oito falhas, quatro sucessos e um IP sinalizado. Abra `reports/demo/report.md` para ler o resultado.

Para repetir, deixe o programa escolher outra pasta:

```bash
python3 logwatch.py data/sample_logins.csv
```

## Entendendo o código

Leia o arquivo `logwatch.py` nesta ordem:

1. `Event` e `Alert`: representam um evento de login e um resultado da detecção.
2. `read_events`: verifica cada registro. Uma linha inválida é contabilizada e recebe uma justificativa; o restante continua sendo analisado. Cabeçalho inválido ou CSV com aspas malformadas interrompe a leitura.
3. `detect_alerts`: separa falhas por IP, ordena os horários e mantém uma janela de tempo usando `deque`.
4. `build_report`: reúne contagens, parâmetros e alertas.
5. `save_database` e `write_results`: gravam os dados em SQLite, JSON e Markdown.
6. `main`: recebe os argumentos e conecta as partes.

Exemplo: falhas nos segundos 0, 15, 30, 45 e 60 entram juntas numa janela de 60 segundos. Uma falha no segundo 61 já não cabe na mesma janela que a do segundo 0. As bordas são inclusivas.

Um sucesso entre as falhas não zera a contagem. O objetivo dessa regra é contar a frequência de falhas, independentemente de sucessos intermediários.

## Três experiências para você fazer

1. Copie o CSV para outro arquivo e mova a quinta falha para `10:03:00Z`. Execute novamente e observe a diferença com o limite padrão.
2. Mantenha o arquivo original e execute com `--threshold 6`: o exemplo deixa de gerar alerta.
3. Execute com `--threshold 3 --window-seconds 300`: o segundo IP que apresentou falhas também pode atingir a regra. Confira os horários no relatório.

Rode os testes após alterar a lógica:

```bash
python3 -m unittest discover -s tests -v
```

## Como apresentar numa entrevista

Depois de estudar e executar, explique com suas palavras:

> Este é um projeto de estudo de análise de autenticação. Ele lê um CSV, valida os registros e identifica concentração de falhas por IP em uma janela de tempo. Usei Python e SQLite para praticar análise de logs e armazenamento. Desenvolvi com apoio de IA e estudei a regra e os testes. Um alerta não confirma um ataque: pode haver falso positivo, principalmente quando várias pessoas compartilham um IP.

Só diga que entende ou modificou uma parte depois de trabalhar nela. Anote suas próprias decisões e alterações no histórico de commits. A primeira versão é uma base de estudo, não uma ferramenta de monitoramento pronta para produção.

## Preparando o repositório

Nome sugerido: `auth-log-analyzer`.

Descrição curta em inglês:

> Python and SQLite tool for analyzing login logs and flagging repeated authentication failures.

Publique a pasta extraída, preservando a estrutura e incluindo os testes e este README. A pasta `reports` está ignorada para evitar adicionar dados analisados por acidente. O arquivo de exemplo contém dados fictícios; use também dados fictícios em demonstrações públicas.

Se você já tem Git configurado e criou um repositório remoto vazio, estes são os comandos locais. Troque `SEU_USUARIO` pelo seu usuário real:

```bash
git init
git add .
git commit -m "Add authentication log analyzer with sample data and tests"
git branch -M main
git remote add origin https://github.com/SEU_USUARIO/auth-log-analyzer.git
git push -u origin main
```

Executar o programa ou os testes não publica alterações automaticamente. Antes de enviar suas mudanças, execute, leia o código e personalize pelo menos uma parte que você consiga explicar.
