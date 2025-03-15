{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    naersk = {
      url = "github:nix-community/naersk";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
    naersk,
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        pkgs = (import nixpkgs) {
          inherit system;
        };

        naersk' = pkgs.callPackage naersk {};
      in {
        # For `nix build` & `nix run`
        packages = {
          default = naersk'.buildPackage {
            src = ./.;
            nativeBuildInputs = with pkgs; [openssl pkg-config];
          };
        };

        # For `nix develop`
        devShells = {
          default = pkgs.mkShell {
            nativeBuildInputs = with pkgs; [rustc cargo rustfmt clippy openssl pkg-config];
          };
        };
      }
    );
}
