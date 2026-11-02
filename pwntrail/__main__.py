import sys


def _entry() -> None:
    # Fast path for the shell hook: skip loading the full CLI.
    if len(sys.argv) >= 2 and sys.argv[1] == "_check":
        args = sys.argv[2:]
        if args and args[0] == "--":
            args = args[1:]
        from .guard import run_check

        sys.exit(run_check(" ".join(args)))
    from .cli import main

    main()


if __name__ == "__main__":
    _entry()
