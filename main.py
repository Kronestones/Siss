"""
main.py — Siss (Sisters of Medusa)
Entry point for the Flask application.
"""

import os
from sisters_web import create_app

app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
