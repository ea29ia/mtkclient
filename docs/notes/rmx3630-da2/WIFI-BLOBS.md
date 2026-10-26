# RMX3630 proprietary Wi-Fi blobs — where and why

**Location:** NOT in this repo (git hook blocks >100 KB binaries).
The archive lives on the PC: `/root/firmware/rmx3630-wifi/wifi-pkg-rmx3630.tar.gz`
(3 240 378 B, sha256 `d9e4b0581785800d40b023c1dbd6c52a2d31c506f6073c7a1cf536e1b3263bc2`).

**Contents (17 files):**
- 8 `.ko` modules from `/vendor/lib/modules/`:
  `wlan_drv_gen4m_6789` (main, 5.4 MB), `wmt_drv` (WMT hub, 2.1 MB),
  `wmt_chrdev_wifi`, `connadp`, `mddp`, `bt_drv_connac1x`, `btif_drv`,
  `oplus_wificapcenter`;
- 5 firmware files from `/vendor/firmware/`: `WIFI_RAM_CODE_soc2_2_{1d,1e}_1.bin`,
  `soc2_2_ram_wifi_{1d,1e}_1_hdr.bin`, `WMT_SOC.cfg`;
- `README.md` with the full inventory.

**vermagic (all modules):** `5.10.209-android12-9-o-05206-g23c1467af8f7 SMP preempt mod_unload modversions aarch64`

**CRC verification (2026-10-26):**
- vs stock baseline (`expected/stock_kernel_required.tsv`): **913/913 match, 0 mismatch**;
- vs our rebuilt CI kernel (run 40316350101, LTO off, OEM defconfig): 616 match / 333 mismatch
  (the known CRC divergence — see `crc-report.txt` in the CI repo).

**Cross-module dependencies:** wlan_drv needs 30 symbols exported by the other
vendor modules (wmt_drv, wmt_chrdev_wifi, connadp, mddp, oplus_wificapcenter)
and 1 via `ccci_md_all` (`mtk_ccci_register_md_state_cb`); zero extra
kernel-required symbols — everything is already in the stock CRC baseline.

**Use cases:** reference for `__versions` CRC patching of the rebuilt kernel;
recovery source if `/vendor` is damaged; research into the connac gen4m driver.

## Related: port-critical bundle (2026-10-26)

`/root/firmware/rmx3630-wifi/port-critical-rmx3630.tar.gz`
(3 033 235 B, sha256 `a5eade1eb83eea20c99494d34bcaea77da69753bdcca3c5c7e1089bc36836c1f`)

16 modules whose sources are ABSENT from the OEM drop, grouped by what a
Linux port cannot live without: full wireless stack (wlan/wmt/bt/gps/fm,
11 modules), touch (gt9886), fingerprint (uff_fp/gf_tee/oplus_fp_common,
3 modules), modem data path (ccci_md_all + ccci_dpmaif). Plus the device
DTB extracted from vendor_boot_a (0x27ba040, 187 KB) and the full
vendor_boot_a dump (64 MB, md5 `9070b1b4…`) as reference.
