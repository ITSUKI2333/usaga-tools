"""Portable entry point. Use python -I -B -S usaga.py ... to suppress site hooks."""
import os,sys
sys.dont_write_bytecode=True
sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
from usaga_tools.cli import main
if __name__=='__main__':
    raise SystemExit(main())
