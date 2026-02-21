﻿# V2rayX

## فارسی
<div dir="rtl" align="right">

`V2rayX` یک کلاینت دسکتاپ ویندوز برای مدیریت و اجرای Xray است. این برنامه مدیریت پروفایل، سابسکریپشن، تست `Ping/Speed`، پراکسی سیستم و Tunnel Mode را در یک رابط ساده ارائه می‌دهد.

### امکانات اصلی
- مدیریت پروفایل‌ها (`vmess`, `vless`, `trojan`, `ss`, `hy2`, `tuic`, `socks`, `wireguard`, ...)
- دریافت و بروزرسانی Subscription
- تست `Ping` و `Speed` برای هر پروفایل
- تنظیم/حذف System Proxy
- پشتیبانی از Tunnel Mode (نیازمند دسترسی ادمین)
- لاگ داخلی برای عیب‌یابی

### پیش‌نیازها
- Windows 10/11 (64-bit)
- `curl` for `Ping/Speed` tests
- Administrator access is required only for Tunnel Mode
- No separate .NET Framework installation is required (packaged exe build)
- `xraycore/xray.exe`
- `xraycore/wintun.dll`
- `xraycore/geoip.dat`
- `xraycore/geosite.dat`

### تصویر محیط فارسی
![راهنمای فارسی](assets/screenshot-fa.png)

</div>

---

## English
`V2rayX` is a Windows desktop client for managing and running Xray.
It provides profile management, subscription updates, `Ping/Speed` tests, system proxy control, and tunnel mode in a single UI.

### Key Features
- Profile management (`vmess`, `vless`, `trojan`, `ss`, `hy2`, `tuic`, `socks`, `wireguard`, ...)
- Subscription fetch and update
- Per-profile `Ping` and `Speed` tests
- Set/Clear System Proxy
- Tunnel mode support (requires Administrator privileges)
- Built-in logs for troubleshooting

### Requirements
- Windows 10/11 (64-bit)
- `curl` for `Ping/Speed` tests (usually available by default on modern Windows)
- Administrator privileges only for Tunnel Mode
- No separate .NET Framework installation is required (packaged exe build)
- `xraycore/xray.exe`
- `xraycore/wintun.dll`
- `xraycore/geoip.dat`
- `xraycore/geosite.dat`

### English Screenshot
![English Guide](assets/screenshot-en.png)

---

## License
MIT
