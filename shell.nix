{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    # Compiler und Build Tools
    gcc
    gnumake
    pkg-config
    valgrind
  ];
  
  shellHook = ''
    echo "Zum builden: make"
    echo "make test"
    echo "make clean"
    echo "make"
    echo "./AES256 e <passwort> <datei>"
    echo "./AES256 d <passwort> <datei>"
  '';
}

