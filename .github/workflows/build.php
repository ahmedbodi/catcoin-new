name: CI Actions for Catcoin

on: [push, pull_request]
jobs:
  build_depends:
    name: Depends-${{ matrix.config.name }}
    runs-on: ${{ matrix.config.os }}
    env:
      APT_BASE: ccache
      SDK_URL: https://bitcoincore.org/depends-sources/sdks
    defaults:
      run:
        shell: bash
    strategy:
      fail-fast: false
      matrix:
        config:
          - name: ARM 32-bit
            os: ubuntu-18.04
            host: arm-linux-gnueabihf
            apt_get: python3 g++-arm-linux-gnueabihf

          - name: AARCH64
            os: ubuntu-18.04
            host: aarch64-linux-gnu
            apt_get: python3 g++-aarch64-linux-gnu

          - name: Win64
            os: ubuntu-18.04
            host: x86_64-w64-mingw32
            apt_get: python3 nsis g++-mingw-w64-x86-64 wine-binfmt wine64

          - name: 32-bit + dash
            os: ubuntu-18.04
            host: i686-pc-linux-gnu
            apt_get: g++-multilib python3-zmq

          - name: x86_64 Linux
            os: ubuntu-18.04
            host: x86_64-unknown-linux-gnu
            apt_get: python3-zmq qtbase5-dev qttools5-dev-tools libqt5svg5-dev libqt5charts5-dev libqrencode-dev protobuf-compiler libdbus-1-dev libharfbuzz-dev libprotobuf-dev
            dep_opts: NO_QT=1 NO_UPNP=1 DEBUG=1 ALLOW_HOST_PACKAGES=1

          - name: macOS 10.14
            os: ubuntu-18.04
            host: x86_64-apple-darwin14
            apt_get: cmake imagemagick libcap-dev librsvg2-bin libz-dev libbz2-dev libtiff-tools python3-dev python3-setuptools
            OSX_SDK: 10.14

    steps:
      - name: Get Source
        uses: actions/checkout@v2

      - name: Setup Environment
        run: |
          sudo apt-get update
          sudo apt-get install --no-install-recommends --no-upgrade -qq "$APT_BASE" ${{ matrix.config.apt_get }}

      - name: Prepare Depends timestamp
        id: depends_cache_timestamp
        shell: cmake -P {0}
        run: |
          string(TIMESTAMP current_date "%Y-%m-%d-%H;%M;%S" UTC)
          message("::set-output name=timestamp::${current_date}")

      - name: depends cache files
        uses: actions/cache@v2
        with:
          path: |
            depends/built
            depends/sdk-sources
            depends/${{ matrix.config.host }}
          key: ${{ runner.os }}-depends-${{ matrix.config.host }}-${{ steps.depends_cache_timestamp.outputs.timestamp }}
          restore-keys: |
            ${{ runner.os }}-depends-${{ matrix.config.host }}-

      - name: Build Depends
        run: |
          export LC_ALL=C.UTF-8
          PATH=$(echo $PATH | tr ':' "\n" | sed '/\/opt\/python/d' | tr "\n" ":" | sed "s|::|:|g")
          # Add llvm-symbolizer directory to PATH. Needed to get symbolized stack traces from the sanitizers.
          PATH=$PATH:/usr/lib/llvm-6.0/bin/
          export PATH
          mkdir -p depends/SDKs depends/sdk-sources
          if [ -n "${{ matrix.config.OSX_SDK }}" -a ! -f depends/sdk-sources/MacOSX${{ matrix.config.OSX_SDK }}.sdk.tar.gz ]; then
            curl --location --fail $SDK_URL/MacOSX${{ matrix.config.OSX_SDK }}.sdk.tar.gz -o depends/sdk-sources/MacOSX${{ matrix.config.OSX_SDK }}.sdk.tar.gz
          fi
          if [ -n "${{ matrix.config.OSX_SDK }}" -a -f depends/sdk-sources/MacOSX${{ matrix.config.OSX_SDK }}.sdk.tar.gz ]; then
            tar -C depends/SDKs -xf depends/sdk-sources/MacOSX${{ matrix.config.OSX_SDK }}.sdk.tar.gz
          fi
          if [[ ${{ matrix.config.host }} = *-mingw32 ]]; then
            BIN=$(which ${{ matrix.config.host }}-g++-posix)
            sudo update-alternatives --set ${{ matrix.config.host }}-g++ $BIN
          fi
          if [ -z "${{ matrix.config.no_depends }}" ]; then
            make -j2 -C depends HOST=${{ matrix.config.host }} ${{ matrix.config.dep_opts }}
          fi

  build_wallet:
    name: ${{ matrix.config.name }}
    runs-on: ${{ matrix.config.os }}
    needs: [build_depends]
    env:
      APT_BASE: ccache
      CCACHE_DIR: ${{ github.workspace }}/.ccache
      CCACHE_SIZE: 500M
      CCACHE_COMPRESS: 1
      WINEDEBUG: fixme-all
      BOOST_TEST_RANDOM: 1${{ github.run_id }}
      TYPE: ${{ matrix.config.type }}
    defaults:
      run:
        shell: bash
    strategy:
      fail-fast: false
      matrix:
        config:
          - name: ARM 32-bit [GOAL:install]  [no unit or functional tests]
            os: ubuntu-18.04
            host: arm-linux-gnueabihf
            apt_get: python3 g++-arm-linux-gnueabihf
            unit_tests: false
            functional_tests: false
            goal: install
            # -Wno-psabi is to disable ABI warnings: "note: parameter passing for argument of type ... changed in GCC 7.1"
            # This could be removed once the ABI change warning does not show up by default
            BITCOIN_CONFIG: "--with-gui=qt5 --enable-glibc-back-compat --enable-reduce-exports --disable-online-rust CXXFLAGS=-Wno-psabi"
            type: linux

          - name: AARCH64 [GOAL:install] [no unit or functional tests]
            os: ubuntu-18.04
            host: aarch64-linux-gnu
            apt_get: python3 g++-aarch64-linux-gnu
            unit_tests: false
            functional_tests: false
            goal: install
            BITCOIN_CONFIG: "--with-gui=qt5 --enable-glibc-back-compat --enable-reduce-exports --disable-online-rust"
            type: linux

          - name: Win64  [GOAL:deploy] [no unit or functional tests]
            os: ubuntu-18.04
            host: x86_64-w64-mingw32
            apt_get: python3 nsis g++-mingw-w64-x86-64 wine-binfmt wine64
            unit_tests: false
            functional_tests: false
            goal: deploy
            BITCOIN_CONFIG: "--with-gui=auto --enable-reduce-exports --disable-online-rust"
            type: windows

          - name: x86_64 Linux  [GOAL:install]  [no unit or functional tests]
            os: ubuntu-18.04
            host: x86_64-unknown-linux-gnu
            apt_get: python3-zmq qtbase5-dev qttools5-dev-tools libqt5svg5-dev libqt5charts5-dev libqrencode-dev protobuf-compiler libdbus-1-dev libharfbuzz-dev libprotobuf-dev
            unit_tests: false
            functional_tests: false
            goal: install
            test_runner_extra: "--coverage --all"
            BITCOIN_CONFIG: "--enable-zmq --with-gui=qt5 --enable-glibc-back-compat --enable-reduce-exports --disable-online-rust"
            type: linux


          - name: macOS 10.10  [GOAL:deploy] [no unit or functional tests]
            os: ubuntu-18.04
            host: x86_64-apple-darwin14
            apt_get: cmake imagemagick libcap-dev librsvg2-bin libz-dev libbz2-dev libtiff-tools python3-dev python3-setuptools
            OSX_SDK: 10.11
            unit_tests: false
            functional_tests: false
            goal: deploy
            BITCOIN_CONFIG: "--enable-gui --enable-reduce-exports --enable-werror --disable-online-rust"
            type: osx

    steps:
      - name: Get Source
        uses: actions/checkout@v2
        with:
          fetch-depth: '1'
          submodules: 'recursive'

      - name: Setup Environment
        run: |
          sudo apt-get update
          sudo apt-get install --no-install-recommends --no-upgrade -qq "$APT_BASE" ${{ matrix.config.apt_get }}
      - name: depends cache files
        if: matrix.config.no_depends != 1
        uses: actions/cache@v2
        with:
          path: |
            depends/built
            depends/sdk-sources
            depends/${{ matrix.config.host }}
          key: ${{ runner.os }}-depends-${{ matrix.config.host }}-
          restore-keys: |
            ${{ runner.os }}-depends-${{ matrix.config.host }}-
      - name: Prepare ccache timestamp
        id: ccache_cache_timestamp
        shell: cmake -P {0}
        run: |
          string(TIMESTAMP current_date "%Y-%m-%d-%H;%M;%S" UTC)
          message("::set-output name=timestamp::${current_date}")
      - name: ccache cache files
        uses: actions/cache@v2
        with:
          path: |
            .ccache
          key: ${{ matrix.config.name }}-ccache-${{ steps.ccache_cache_timestamp.outputs.timestamp }}
          restore-keys: |
            ${{ matrix.config.name }}-ccache-
      - name: Build Wallet
        run: |
          export LC_ALL=C.UTF-8
          echo $CCACHE_DIR
          PATH=$(echo $PATH | tr ':' "\n" | sed '/\/opt\/python/d' | tr "\n" ":" | sed "s|::|:|g")
          # Add llvm-symbolizer directory to PATH. Needed to get symbolized stack traces from the sanitizers.
          PATH=$PATH:/usr/lib/llvm-6.0/bin/
          export PATH
          mkdir -p depends/SDKs depends/sdk-sources
          if [ -n "${{ matrix.config.OSX_SDK }}" -a ! -f depends/sdk-sources/MacOSX${{ matrix.config.OSX_SDK }}.sdk.tar.gz ]; then
            curl --location --fail $SDK_URL/MacOSX${{ matrix.config.OSX_SDK }}.sdk.tar.gz -o depends/sdk-sources/MacOSX${{ matrix.config.OSX_SDK }}.sdk.tar.gz
          fi
          if [ -n "${{ matrix.config.OSX_SDK }}" -a -f depends/sdk-sources/MacOSX${{ matrix.config.OSX_SDK }}.sdk.tar.gz ]; then
            tar -C depends/SDKs -xf depends/sdk-sources/MacOSX${{ matrix.config.OSX_SDK }}.sdk.tar.gz
          fi
          if [[ ${{ matrix.config.host }} = *-mingw32 ]]; then
            BIN=$(which ${{ matrix.config.host }}-g++-posix)
            sudo update-alternatives --set ${{ matrix.config.host }}-g++ $BIN
            sudo update-binfmts --import /usr/share/binfmts/wine
          fi
          OUTDIR_PATH="$GITHUB_WORKSPACE/$GITHUB_RUN_NUMBER-${{ matrix.config.host }}"
          if [ -n "${{ matrix.config.OSX_SDK }}" ]; then mkdir -p ${OUTDIR_PATH}/bin; fi
          BITCOIN_CONFIG_ALL="--disable-dependency-tracking --prefix=$GITHUB_WORKSPACE/depends/${{ matrix.config.host }} --bindir=$OUTDIR_PATH/bin --libdir=$OUTDIR_PATH/lib"
          echo ::group::Autogen
          ./autogen.sh
          echo ::endgroup::
          mkdir build && cd build
          echo ::group::Configure
          ../configure --cache-file=config.cache $BITCOIN_CONFIG_ALL ${{ matrix.config.BITCOIN_CONFIG }} $PARAMS_FLAGS || ( cat config.log && false)
          echo ::endgroup::
          echo ::group::Distdir
          make distdir VERSION=${{ matrix.config.host }}
          echo ::endgroup::
          cd catcoin-${{ matrix.config.host }}
          echo ::group::Configure
          ./configure --cache-file=../config.cache $BITCOIN_CONFIG_ALL ${{ matrix.config.BITCOIN_CONFIG }} $PARAMS_FLAGS || ( cat config.log && false)
          echo ::endgroup
          echo ::group::Build
          make -j2 ${{ matrix.config.goal }} || ( echo "Build failure. Verbose build follows." && make ${{ matrix.config.goal }} V=1 ; false )
          echo ::endgroup::
          if [ "${{ matrix.config.unit_tests }}" = "true" ]; then
            echo ::group::Unit-Tests
            LD_LIBRARY_PATH=$GITHUB_WORKSPACE/depends/"${{ matrix.config.host }}"/lib make -j2 check VERBOSE=1
            echo ::endgroup::
          fi
          if [ "${{ matrix.config.functional_tests }}" = "true" ]; then
            echo ::group::Functional-Tests
            test/functional/test_runner.py --combinedlogslen=4000 ${{ matrix.config.test_runner_extra }}
            echo ::endgroup::
          fi
          echo ::group::Zip-Artifacts
          if [ "$TYPE" == "windows" ]; then
            echo "Windows";
            mkdir -p ${OUTDIR_PATH};
            cp -rf ./release ${OUTDIR_PATH};
          fi

          if [ "$TYPE" == "osx" ]; then
            echo "OSX";
            mkdir -p ${OUTDIR_PATH};
            cp -rf Catcoin-Core.dmg ${OUTDIR_PATH};
            cp -rf Catcoin-Qt.app ${OUTDIR_PATH};
          fi
          cd $GITHUB_WORKSPACE && tar -zcvf catcoin-${{ matrix.config.host }}.tar.gz ${OUTDIR_PATH}
          echo ::endgroup::

      - name: Upload binaries to release
        uses: svenstaro/upload-release-action@v2
        with:
          repo_token: ${{ secrets.GITHUB_TOKEN }}
          file: ${{ github.workspace }}/catcoin-${{ matrix.config.host }}.tar.gz
          asset_name: ${{ github.sha }}-catcoin-${{ matrix.config.host }}.tar.gz
          tag: ${{ github.ref }}
