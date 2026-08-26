{
  description = "git-vault — an append-only, Git-native, hardware-backed secret vault";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      ...
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      perSystem =
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ (import rust-overlay) ];
          };
          rustToolchain = pkgs.rust-bin.stable."1.87.0".default.override {
            extensions = [
              "clippy"
              "rust-src"
              "rustfmt"
            ];
          };
          rustPlatform = pkgs.makeRustPlatform {
            cargo = rustToolchain;
            rustc = rustToolchain;
          };
          nativeBuildInputs = [ pkgs.pkg-config ];
          buildInputs = pkgs.lib.optionals pkgs.stdenv.isLinux [ pkgs.pcsclite ];
          source = pkgs.lib.cleanSourceWith {
            src = ./.;
            filter =
              path: _type:
              let
                name = baseNameOf (toString path);
              in
              name != ".git" && name != "target";
          };
          gitVault = rustPlatform.buildRustPackage {
            pname = "git-vault";
            version = "0.1.0";
            src = source;

            cargoLock.lockFile = ./Cargo.lock;

            inherit nativeBuildInputs buildInputs;

            meta = {
              description = "An append-only, Git-native, hardware-backed secret vault";
              homepage = "https://github.com/TrystinDuffy/nit";
              license = pkgs.lib.licenses.mit;
              mainProgram = "git-vault";
              platforms = systems;
            };
          };
        in
        {
          inherit
            buildInputs
            nativeBuildInputs
            gitVault
            pkgs
            rustToolchain
            ;
        };
    in
    {
      packages = forAllSystems (system: {
        default = (perSystem system).gitVault;
        git-vault = (perSystem system).gitVault;
      });

      apps = forAllSystems (system: {
        default = {
          type = "app";
          program = "${(perSystem system).gitVault}/bin/git-vault";
        };
      });

      checks = forAllSystems (system: {
        default = (perSystem system).gitVault;
      });

      devShells = forAllSystems (
        system:
        let
          env = perSystem system;
        in
        {
          default = env.pkgs.mkShell {
            packages = [
              env.rustToolchain
              env.pkgs.gnumake
              env.pkgs.pkg-config
            ] ++ env.buildInputs;

            LD_LIBRARY_PATH = env.pkgs.lib.optionalString env.pkgs.stdenv.isLinux (
              env.pkgs.lib.makeLibraryPath env.buildInputs
            );
          };
        }
      );

      formatter = forAllSystems (system: (perSystem system).pkgs.nixfmt-rfc-style);
    };
}
