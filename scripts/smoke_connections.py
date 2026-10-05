"""Small connection smoke test; equivalent to `python -m guardian doctor`."""

from guardian.cli import doctor

if __name__ == "__main__":
    doctor(config=None)
