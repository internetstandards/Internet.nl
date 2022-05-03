This is a short list of what custom dependencies are installed for internet.nl. This helps with creating tooling
to quickly move and re-install these dependencies when there is a minor version update with pip-sync. It prevents
compiling unbound and such over and over, because pip-sync has no option to tell which dependencies are OK to keep.