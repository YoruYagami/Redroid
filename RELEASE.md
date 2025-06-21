# Release Pipeline

Questo documento descrive il processo di rilascio automatico per Redroid.

## 🚀 Processo di Release

### 1. Preparazione della Release

Prima di creare una nuova release, assicurati di:

1. **Incrementare la versione** in `pyproject.toml`:
   ```toml
   [project]
   name = "redroid"
   version = "1.0.2"  # Incrementa qui
   ```

2. **Committare le modifiche**:
   ```bash
   git add pyproject.toml
   git commit -m "Bump version to 1.0.2"
   git push
   ```

### 2. Creazione del Tag e Release

1. **Creare il tag**:
   ```bash
   git tag v1.0.2
   git push origin v1.0.2
   ```

2. **Creare la release su GitHub**:
   - Vai su https://github.com/YoruYagami/Redroid/releases/new
   - Seleziona il tag `v1.0.2`
   - Aggiungi titolo: "Release 1.0.2"
   - Aggiungi descrizione delle modifiche
   - Clicca "Publish release"

### 3. Pipeline Automatica

Una volta pubblicata la release, il workflow GitHub Actions si attiva automaticamente:

```
Tag → Build → PyPI Upload → Sigstore Signing → GitHub Release Assets
```

#### Jobs del Workflow:

1. **Build** 📦
   - Compila il package (wheel + sdist)
   - Cache delle dipendenze pip
   - Salva gli artifacts

2. **Publish** 🐍
   - Pubblica su PyPI usando OIDC
   - Solo per tag che iniziano con `refs/tags/`
   - Skip automatico se la versione esiste già

3. **GitHub Release** 🔐
   - Firma i package con Sigstore
   - Allega i file firmati alla release GitHub

## ⚠️ Requisiti Importanti

### Versioning
- **OBBLIGATORIO**: Incrementare la versione prima di ogni release
- PyPI rifiuta upload di versioni duplicate (errore 400)
- Usa [Semantic Versioning](https://semver.org/): `MAJOR.MINOR.PATCH`

### Esempi di Bump:
```bash
# Bug fix
1.0.1 → 1.0.2

# Nuove funzionalità
1.0.2 → 1.1.0

# Breaking changes
1.1.0 → 2.0.0
```

## 🛠️ Configurazione

### GitHub Environments
Il workflow usa environment protetti:
- `pypi`: Per la pubblicazione su PyPI
- Configurabile con secrets e approvazioni manuali

### Permissions
- `id-token: write`: Per OIDC con PyPI
- `contents: write`: Per upload assets su GitHub Release

## 📦 Installazione

Una volta pubblicato, il package è disponibile via:

```bash
pip install redroid
```

## 🔍 Troubleshooting

### Errore "filename has already been used"
- **Causa**: Tentativo di upload della stessa versione
- **Soluzione**: Incrementa la versione in `pyproject.toml`

### Workflow fallisce
- Controlla i logs su GitHub Actions
- Verifica che il tag sia nel formato corretto (`v1.0.x`)
- Assicurati che gli environment siano configurati

### Cache issues
- Il workflow usa cache per pip dependencies
- In caso di problemi, cancella la cache dalle Actions settings

## 📝 Note

- Il workflow include `concurrency` per evitare release simultanee
- `skip-existing: true` previene errori se il package esiste già
- La firma Sigstore fornisce verificabilità crittografica
