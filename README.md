# quart-enciphers

Encrypted session interface for Quart using [enciphers](https://pypi.org/project/enciphers/).

Replaces Quart's default signed cookie session with a fully encrypted one.

## Installation

```bash
pip install quart-enciphers
```

## Usage

```python
from quart import Quart, session
from quart_enciphers import EnciphersSession

app = Quart(__name__)
EnciphersSession(app)

@app.route("/login")
async def login():
    session["user_id"] = 1
    return "logged in"
```

### Application Factory Pattern

```python
from quart_enciphers import EnciphersSession

es = EnciphersSession()

def create_app():
    app = Quart(__name__)
    es.init_app(app)
    return app
```

## Configuration

| Key | Type | Default | Description |
|---|---|---|---|
| `ENCIPHERS_STEP` | `int` | random | Encryption step |
| `ENCIPHERS_KEY` | `int` | random | Secret key |
| `ENCIPHERS_KEY_ENV` | `str` | None | Environment variable for key |

> If no configuration is provided, random values are generated at startup.

## License

Apache-2.0 — Copyright 2026 Mejlad Alsubaie
