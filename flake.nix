{
  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    mozillapkgs = {
      url = "github:mozilla/nixpkgs-mozilla";
      flake = false;
    };
    naersk.url = "github:nmattia/naersk";
    nixpkgs.url = "github:nixos/nixpkgs/20.09";
  };

  outputs = { self, nixpkgs, flake-utils, mozillapkgs, naersk }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        legacyPkgs = nixpkgs.legacyPackages."${system}";

        pkgs = import nixpkgs {
          inherit system;
          config = {
            # Due to uncertainty around DFINITY SDK license
            allowUnfree = true;
          };
          overlays = [
            (final: prev: (import
              # (legacyPkgs.fetchFromGitHub {
              #   owner = "paulyoung";
              #   repo = "nixpkgs-dfinity-sdk";
              #   rev = "main";
              #   sha256 = legacyPkgs.lib.fakeSha256;
              # })
              (builtins.fetchGit {
                url = "ssh://git@github.com/paulyoung/nixpkgs-dfinity-sdk.git";
                ref = "main";
                rev = "88b9606db7e26834b24d83297fd436473bc4a138";
              })
            ) final prev)
          ];
        };

        # Get a specific rust version
        mozilla = pkgs.callPackage (mozillapkgs + "/package-set.nix") {};
        rust = (mozilla.rustChannelOf {
          # hyper depends on socket2 which requires at least rust 1.46.0
          # naersk requires cargo nightly: https://github.com/nmattia/naersk/issues/100
          #
          # TODO: stable toolchain with compatible nightly build of cargo (see
          # above issue)
          date = "2020-08-27"; # Date of 1.46.0 announcement
          channel = "nightly";
          sha256 = "0d9bna9l8w7sps7hqjq35835p2pp73dvy3y367b0z3wg1ha7gvjj";
        }).rust.override {
          extensions = [
            "clippy-preview"
            # "miri-preview"
            # "rls-preview"
            # "rust-analyzer-preview"
            "rustfmt-preview"
            # "llvm-tools-preview"
            # "rust-analysis"
            # "rust-std"
            # "rustc-dev"
            # "rustc-docs"
            "rust-src"
          ];
          targets = [
            "wasm32-unknown-unknown"
          ];
        };

        # Override the version used in naersk
        naersk-lib = naersk.lib."${system}".override {
          cargo = rust;
          rustc = rust;
        };

        dfinitySdk = (pkgs.dfinity-sdk {
          acceptLicenseAgreement = true;
          sdkSystem = system;
        })."0_7_0-beta_8";
      in
        rec {
          # `nix build`
          packages.icx-proxy = naersk-lib.buildPackage rec {
            pname = "icx-proxy";
            root = ./.;
            buildInputs = [] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
              pkgs.darwin.apple_sdk.frameworks.Security
              pkgs.libiconv

              # https://nixos.wiki/wiki/Rust#Building_the_openssl-sys_crate
              pkgs.openssl_1_1
              pkgs.pkgconfig
            ];
            cargoBuildOptions = x: x ++ [
              "--package" pname
            ];
            cargoTestOptions = x: x ++ [
              "--package" pname
            ];
          };

          defaultPackage = packages.codebase;


          # `nix run`

          apps.icx-proxy = flake-utils.lib.mkApp {
            drv = packages.icx-proxy;
          };

          defaultApp = apps.icx-proxy;


          # `nix develop`
          devShell = pkgs.mkShell {
            buildInputs = [
              dfinitySdk
            ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
              pkgs.libiconv
            ];
            # supply the specific rust version
            nativeBuildInputs = [ rust ];
          };
        }
    );
}
