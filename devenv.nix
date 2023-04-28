{ pkgs, ... }:
{

  packages = [
    pkgs.gnumake
    pkgs.docker-compose
    pkgs.colima
    pkgs.podman
    pkgs.blockdiag
    pkgs.python39
    pkgs.python39Packages.pip
  ];

  enterShell = ''
    export $(grep COMPOSE_FILE develop.env)
  '';
}
