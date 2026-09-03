{
  description = "tailcat: userspace TCP over WireGuard and DERP, implemented in Rust";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        meta = {
          description = "Control-plane-free TCP over WireGuard and DERP";
          homepage = "https://github.com/spullara/tailcat-rs";
          license = pkgs.lib.licenses.bsd3;
          mainProgram = "tailcat";
        };
      in
      {
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "tailcat";
          version = self.shortRev or "dev";
          src = self;
          cargoLock.lockFile = ./Cargo.lock;
          nativeBuildInputs = [ pkgs.cmake pkgs.pkg-config ];
          cargoBuildFlags = [ "--bin" "tailcat" ];
          cargoTestFlags = [ "--lib" ];
          inherit meta;
        };

        devShells.default = pkgs.mkShell {
          packages = [ pkgs.cargo pkgs.rustc pkgs.rustfmt pkgs.clippy pkgs.cmake pkgs.pkg-config ];
        };
      });
}
