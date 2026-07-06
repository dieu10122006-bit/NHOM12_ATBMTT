import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "web"))

os.chdir(os.path.dirname(os.path.abspath(__file__)))

from web.app import app

if __name__ == "__main__":
    app.run()