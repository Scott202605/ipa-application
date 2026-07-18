# IPAd Manager Install Delivery

This guide describes how to build and hand off IPAd Manager as a release tarball for one Linux device. It does not install files into system directories automatically.

## Build

```bash
cmake -S . -B build-manager -DIPAD_BUILD_TESTS=ON
cmake --build build-manager --parallel
ctest --test-dir build-manager --output-on-failure
```

For a real SDK header build:

```bash
cmake -S . -B build-manager-real-sdk -DIPAD_BUILD_TESTS=ON -DIPAD_WORKER_ENABLE_REAL_SDK=ON
cmake --build build-manager-real-sdk --parallel
```

## Create Release Tarball

```bash
mkdir -p /tmp/ipad-release
sh packaging/make-release-tarball.sh build-manager /tmp/ipad-release
```

The script prints the generated tarball path:

```text
/tmp/ipad-release/ipad-manager-release.tar.gz
```

Inspect the manifest before handoff:

```bash
tar -tzf /tmp/ipad-release/ipad-manager-release.tar.gz
cat /tmp/ipad-release/ipad-manager-release/MANIFEST.txt
```

## Manual Install Layout

On the target device, unpack the tarball and copy files according to the selected service profile:

```bash
tar -xzf ipad-manager-release.tar.gz
sudo install -m 0755 ipad-manager-release/bin/ipad-managerd /usr/local/bin/ipad-managerd
sudo install -m 0755 ipad-manager-release/bin/ipad-sdk-worker /usr/local/bin/ipad-sdk-worker
sudo install -m 0755 ipad-manager-release/bin/ipadctl /usr/local/bin/ipadctl
sudo mkdir -p /etc/ipad-manager /var/lib/ipad-manager /var/log/ipad-manager /run/ipad-manager
```

Generate config on the device:

```bash
ipadctl platform check
ipadctl bootstrap check --mock
sudo ipadctl setup --mock
```

For real AT serial mode:

```bash
ipadctl device list
ipadctl bootstrap check --real --at-device /dev/ttyUSB2
sudo ipadctl setup --real --at-device /dev/ttyUSB2
```

## Choose Service Profile

- systemd: use `ipad-manager-release/packaging/systemd/`.
- OpenRC: use `ipad-manager-release/packaging/openrc/`.
- SysV init: use `ipad-manager-release/packaging/sysvinit/`.
- Custom supervisor: use `ipad-manager-release/packaging/manual/`.

`ipadctl bootstrap check` gives platform-aware restart guidance.

## Validate Install

```bash
ipadctl platform check
ipadctl config show
ipadctl config check
ipadctl doctor
```

If validation fails, use `docs/troubleshooting-guide.md` from the release package.
