# Development start

Development setup is mostly done through the Makefile, which handles many of
the tasks.

First, install the required system requirements from the
[installation instructions](Installation.md) or alternatives for your OS.

```bash
git clone https://github.com/internetstandards/Internet.nl/
cd Internet.nl
make venv

# Install separate dependencies, for which no wheels are available:
# Note that unbound comes in a variety of flavors in the makefile(!)
make unbound
make nassl

# Run the application, and the workers
make run
make run-worker
make run-heartbeat
```

Running tests is not yet streamlined, it requires a test worker to be ran at
the same time:
```bash
make run-testworker
make test
```

## M1 Mac

The dependencies are currently x86_64 only. So M1 Mac users need to run `arch -x86_64 /bin/sh` before continuing.
The Makefile does this already as well.
