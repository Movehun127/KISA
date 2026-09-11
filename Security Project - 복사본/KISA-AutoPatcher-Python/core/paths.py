"""Read versioned resources from the build; write results beside the executable."""
import sys
from pathlib import Path

RESOURCE_DIR = Path(getattr(sys, '_MEIPASS', Path(__file__).resolve().parents[1]))
OUTPUT_DIR = Path(sys.executable).parent if getattr(sys, 'frozen', False) else RESOURCE_DIR
POLICY_DIR = RESOURCE_DIR / 'config' / 'policies'
