import os
from sisters_web import create_app
from sisters_invites import init_invite_tables

app = create_app()
init_invite_tables()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
