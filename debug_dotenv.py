import os

from dotenv import load_dotenv

# Debug the .env file loading with auth/config.py path
print("Current file:", __file__)
print("Current dir:", os.path.dirname(os.path.abspath(__file__)))

# Simulate how the path would be calculated from auth/config.py
config_file_path = os.path.join(os.getcwd(), "auth", "config.py")
print("Config file path:", config_file_path)
current_dir = os.path.dirname(os.path.abspath(config_file_path))
print("Current dir (from config path):", current_dir)
project_root = os.path.dirname(current_dir)  # Go up from auth/ to get to project root
print("Project root (from config path):", project_root)
print(".env path:", os.path.join(project_root, ".env"))
print("test.env path:", os.path.join(project_root, "test.env"))
print("Does .env exist?", os.path.exists(os.path.join(project_root, ".env")))
print("Does test.env exist?", os.path.exists(os.path.join(project_root, "test.env")))

# Try to load dotenv and check values

load_dotenv(os.path.join(project_root, ".env"))
