# BOLA AI — Quick Start

Local, offline AI tool for finding Broken Object-Level Authorization (BOLA) vulnerabilities in API documentation.

## Prerequisites

- **Docker** installed
- ~6 GB free disk space
- Internet for the first run only (pulls image + model)

## Run it (one command)

```bash
docker run -p 8000:8000 -v ~/my-docs:/shared-docs ghcr.io/igorredkach/bolai:latest
```

Replace `~/my-docs` with the path to a folder where you'll put your API documentation.

**First run takes 3-10 minutes** (downloads the LLM model). After that, it starts in under a minute.

## Use it

1. Open **http://localhost:8000/chat**
2. Copy your API documentation (markdown, text files) into the folder you mounted (`~/my-docs` in the example above)
3. In the chat, type **`ingest`** — the tool loads all your files
4. Ask questions: *"What BOLA risks exist?"*, *"Generate curl commands to test BOLA"*
5. Type **`help`** for the full command reference

## Examples

Mount your current directory:
```bash
docker run -p 8000:8000 -v ./docs:/shared-docs ghcr.io/igorredkach/bolai:latest
```

Mount an absolute path:
```bash
docker run -p 8000:8000 -v /home/user/api-specs:/shared-docs ghcr.io/igorredkach/bolai:latest
```

Run in background:
```bash
docker run -d --name bola-ai -p 8000:8000 -v ~/my-docs:/shared-docs ghcr.io/igorredkach/bolai:latest
```

## Chat commands

| Command | What it does |
|---|---|
| `help` | Full usage guide |
| `ingest` | Load all files from your mounted folder |
| `ingest <filename>` | Load one specific file |
| `list files` | Show what's in the folder |
| `status` | System health |
| `reset` | Clear loaded documents |

## Stop

```bash
docker stop bola-ai
```

## Persistent data (optional)

To keep the model cached between runs (skip the first-run download next time):

```bash
docker run -p 8000:8000 \
  -v ~/my-docs:/shared-docs \
  -v bola-data:/data \
  -v bola-ollama:/root/.ollama \
  ghcr.io/igorredkach/bolai:latest
```

## Troubleshooting

| Problem | Fix |
|---|---|
| First run is slow | Normal — downloading ~1 GB model. Wait 3-10 min. |
| Analysis takes long | LLM runs on CPU. 1-4 minutes per question is normal. |
| Port 8000 in use | Use `-p 9000:8000` and open `http://localhost:9000/chat` |
