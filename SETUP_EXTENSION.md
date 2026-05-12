# 🚀 Setup & Run Extension - AI Scam Protection v2.0.1

## ✅ Server Running

Local server is running on `http://localhost:8000`

---

## 📋 How to Load Extension in Chrome

### Step 1: Open Chrome Extensions Page
```
1. Open Chrome browser
2. Go to: chrome://extensions/
3. Or: Menu → More tools → Extensions
```

### Step 2: Enable Developer Mode
```
1. Look for "Developer mode" toggle (top right)
2. Click to enable it
3. You should see new buttons appear
```

### Step 3: Load Unpacked Extension
```
1. Click "Load unpacked" button
2. Navigate to: browser_extension folder
3. Select the folder
4. Click "Select Folder"
```

### Step 4: Extension Loaded!
```
You should see:
✅ "AI Scam Protection" extension in the list
✅ Extension icon in toolbar
✅ No errors in the extension
```

---

## 🧪 Test the Extension

### Open Dashboard
```
1. Click the extension icon in toolbar
2. Click "Dashboard"
3. Dashboard should open without errors
```

### Test Real-Time Stats
```
1. Look at stats grid
2. Should show:
   - Threats Blocked: 0
   - Scans Today: 0
   - Protection Score: 79
   - Uptime: 24h
```

### Test Threat Scanner
```
1. Scroll to "AI Scam Protection Scanner"
2. Paste URL: https://tiktok-free-download.com
3. Click "Scan now"
4. Should show: THREAT DETECTED (Prize Scam)
```

### Test VPN
```
1. Scroll to "Browse privately"
2. Click "Turn on" button
3. Should show: "VPN is ON (Country)"
4. Click "Turn off" to disable
```

---

## 📁 File Structure

```
browser_extension/
├── manifest.json              ✅ Extension config
├── background.js              ✅ Real-time service
├── content.js                 ✅ Page warnings
├── dashboard.html             ✅ Dashboard UI
├── dashboard.js               ✅ Dashboard logic
├── dashboard.css              ✅ Dashboard styles
├── threat-detector.js         ✅ Threat detection
├── vpn-manager.js             ✅ VPN management
├── popup.html                 ✅ Popup UI
├── popup.js                   ✅ Popup logic
├── blocked.html               ✅ Blocked page
├── blocked.js                 ✅ Blocked page logic
└── blocked.css                ✅ Blocked page styles
```

---

## 🔍 Check for Errors

### Open Developer Console
```
1. Open dashboard
2. Press F12 (or Ctrl+Shift+I)
3. Go to "Console" tab
4. Look for red error messages
5. Should see NO red errors
```

### Check Background Service
```
1. Go to chrome://extensions/
2. Find "AI Scam Protection"
3. Click "Service worker" link
4. Check console for errors
```

---

## ✅ Verification Checklist

- [ ] Extension loads in chrome://extensions/
- [ ] Extension icon appears in toolbar
- [ ] Dashboard opens without errors
- [ ] Stats display correctly
- [ ] Threat scanner works
- [ ] VPN button works
- [ ] No red errors in console
- [ ] Threat feed displays
- [ ] Protection status shows

---

## 🎯 Quick Test URLs

### Malicious URLs (Should be detected)
```
✅ https://tiktok-free-download.com
   Expected: MALICIOUS (Prize Scam)

✅ https://secure-login-verify.com
   Expected: MALICIOUS (Banking Phishing)

✅ https://claim-your-prize-now.com
   Expected: MALICIOUS (Prize Scam)
```

### Safe URLs (Should pass)
```
✅ https://google.com
   Expected: SAFE

✅ https://amazon.com
   Expected: SAFE

✅ https://github.com
   Expected: SAFE
```

---

## 🆘 Troubleshooting

### Extension doesn't load
```
1. Check manifest.json syntax
2. Verify all files exist
3. Reload extension (F5)
4. Check console for errors
```

### Dashboard doesn't open
```
1. Reload extension
2. Clear cache (chrome://extensions/ → Clear data)
3. Check console for errors
4. Try opening again
```

### Scanner doesn't work
```
1. Check if threat-detector.js is loaded
2. Reload extension
3. Check console for errors
4. Try scanning again
```

### VPN doesn't work
```
1. Check if vpn-manager.js is loaded
2. Reload extension
3. Check console for errors
4. Try toggling VPN again
```

---

## 📞 Support

If you encounter issues:

1. **Check Console** (F12)
   - Look for red error messages
   - Note the exact error

2. **Reload Extension**
   - Go to chrome://extensions/
   - Click refresh icon

3. **Clear Data**
   - Go to chrome://extensions/
   - Click "Clear data"
   - Reload extension

4. **Check Files**
   - Verify all files exist
   - Check file permissions
   - Verify no syntax errors

---

## 🎉 You're Ready!

The extension is ready to use. Follow the steps above to load it in Chrome and start testing!

**Version**: 2.0.1
**Status**: ✅ Ready to Run
**Date**: May 9, 2026

---

## 📚 Documentation

- **QUICK_START.md** - Quick reference
- **TESTING_GUIDE.md** - Complete testing checklist
- **ADVANCED_FEATURES.md** - Feature documentation
- **FIX_GUIDE.md** - Error fix explanation

---

**Happy testing! 🛡️**
