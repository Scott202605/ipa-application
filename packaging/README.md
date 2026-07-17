# IPAd Manager Packaging

This directory contains Linux deployment artifacts for the single-device IPAd Manager service.

## Runtime paths

- Socket: `/run/ipad-manager/ipad-manager.sock`
- Config: `/etc/ipad-manager/config.json`
- State: `/var/lib/ipad-manager`
- Logs: `/var/log/ipad-manager`

## Service user

Create an `ipad` user and group, then grant serial or PC/SC permissions through udev rules selected for the target device transport.
