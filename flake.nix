{
  description = "A WireGuard configuration utility for Private Internet Access";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      nixpkgs,
      flake-utils,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            wireguard-tools
            openresolv

            python3
            python3Packages.pip
            python3Packages.virtualenv
          ];

          shellHook = ''
            if [ ! -d ".venv" ]; then
              echo "Creating Python virtual environment..."
              ${pkgs.python3}/bin/python -m venv .venv
            fi

            source .venv/bin/activate

            if [ ! -f ".venv/.requirements-installed" ]; then
              echo "Installing Python dependencies..."
              pip install -r requirements.txt
              touch .venv/.requirements-installed
            fi

            export PATH="$PWD:$PATH"

            echo ""
            echo "PIA-WG development environment activated"
            echo ""
          '';
        };
      }
    );
}
