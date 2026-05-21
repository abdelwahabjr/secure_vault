from config import Config
print("DIRECT TEST:", Config.GOOGLE_CLIENT_ID)

from app import create_app

app = create_app()

if __name__ == "__main__":
    app.run(debug=True)