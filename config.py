
import os

class Config:

    SECRET_KEY = os.environ.get("SECRET_KEY")

    SESSION_DURATION_MINUTES = 30
