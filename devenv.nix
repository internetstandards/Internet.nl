{ pkgs, ... }:
{

  packages = [
    pkgs.gnumake
    pkgs.docker-compose
    pkgs.colima
    pkgs.podman
    pkgs.python39
    pkgs.python39Packages.pip
    pkgs.python39Packages.diagrams
  ];

  enterShell = ''
    export $(grep COMPOSE_FILE develop.env)
  '';
}
