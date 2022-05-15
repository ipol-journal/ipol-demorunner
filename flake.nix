{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
    naersk.url = "github:nix-community/naersk";
    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, flake-utils, naersk, flake-compat }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        pkgs = nixpkgs.legacyPackages."${system}";
        naersk-lib = naersk.lib."${system}";
      in
        rec {
          # `nix build`
          packages.ipol-demorunner = naersk-lib.buildPackage {
            pname = "ipol-demorunner";
            root = ./.;
            nativeBuildInputs = with pkgs; [ openssl pkgconfig ];
          };
          defaultPackage = packages.ipol-demorunner;

          # `nix run`
          apps.ipol-demorunner = flake-utils.lib.mkApp {
            drv = packages.ipol-demorunner;
          };
          defaultApp = apps.ipol-demorunner;

          # `nix develop`
          devShell = pkgs.mkShell {
            nativeBuildInputs = with pkgs; [ rustc cargo openssl pkgconfig ];
          };
        }
    );
}
