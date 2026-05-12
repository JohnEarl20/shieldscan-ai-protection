# Testing Guide - AI Scam Protection v2.0

## 🧪 Complete Testing Checklist

### Step 1: Reload Extension
```
1. Go to chrome://extensions/
2. Find "AI Scam Protection"
3. Click the refresh icon (circular arrow)
4. Wait for extension to reload
```

### Step 2: Open Dashboard
```
1. Click the extension icon in toolbar
2. Click "Dashboard"
3. Dashboard should open without errors
4. Check browser console (F12) for any red errors
```

---

## ✅ Test Real-Time Stats

### Test 1: Stats Display
```
Expected:
- Threats Blocked: 0 (or higher)
- Scans Today: 0 (or higher)
- Protection Score: 79
- Uptime: 24h

Action:
1. Open dashboard
2. Look at stats grid
3. Verify all 4 stats display
```

### Test 2: Stats Update
```
Expected:
- Stats update every 5 seconds
- Numbers may change
- Animation pulse effect

Action:
1. Open dashboard
2. Watch stats for 10 seconds
3. Verify they update
```

---

## ✅ Test Threat Feed

### Test 1: Threat Feed Display
```
Expected:
- Live Threat Feed section visible
- Shows "System initialized" message
- Feed is scrollable

Action:
1. Open dashboard
2. Scroll down to "Live Threat Feed"
3. Verify it displays
```

### Test 2: Add Threat to Feed
```
Expected:
- New threats appear in feed
- Animated slide-in effect
- Shows threat details

Action:
1. Open dashboard
2. Use scanner to detect threat
3. Verify threat appears in feed
```

---

## ✅ Test Protection Status

### Test 1: Status Display
```
Expected:
- Main Shield: 🟢 Active
- Scanner: 🔍 Ready
- Definitions: ✓ Latest
- System: ✓ Normal

Action:
1. Open dashboard
2. Look at Protection Status Panel
3. Verify all 4 statuses display
```

### Test 2: Status Updates
```
Expected:
- Status updates every 10 seconds
- May show different states

Action:
1. Open dashboard
2. Watch status for 20 seconds
3. Verify they update
```

---

## ✅ Test Advanced Scanner

### Test 1: Scan Malicious URL
```
URL: https://tiktok-free-download.com

Expected:
- Scanner shows "Analyzing..."
- Result: THREAT DETECTED
- Shows threat type (Prize Scam)
- Shows threat details

Action:
1. Open dashboard
2. Paste URL in scanner
3. Click "Scan now"
4. Verify threat detected
```

### Test 2: Scan Safe URL
```
URL: https://google.com

Expected:
- Scanner shows "Analyzing..."
- Result: Looks safe!
- No threats detected

Action:
1. Open dashboard
2. Paste URL in scanner
3. Click "Scan now"
4. Verify safe result
```

### Test 3: Scan Phishing URL
```
URL: https://secure-login-verify.com

Expected:
- Scanner shows "Analyzing..."
- Result: THREAT DETECTED
- Shows threat type (Banking Phishing)

Action:
1. Open dashboard
2. Paste URL in scanner
3. Click "Scan now"
4. Verify phishing detected
```

### Test 4: Scan Text
```
Text: "Congratulations! You won $1,000,000! Claim your prize now!"

Expected:
- Switch to "Paste text" tab
- Paste text
- Click "Scan now"
- Result: THREAT DETECTED (Prize Scam)

Action:
1. Open dashboard
2. Click "Paste text" tab
3. Paste text
4. Click "Scan now"
5. Verify scam detected
```

---

## ✅ Test VPN - Browse Privately

### Test 1: Enable VPN
```
Expected:
- "Turn on" button changes to "Connecting..."
- After 2-5 seconds: "Turn off" button appears
- Status shows "VPN is ON (Country)"
- Button turns green

Action:
1. Open dashboard
2. Scroll to "Browse privately"
3. Click "Turn on" button
4. Wait for connection
5. Verify status changes
```

### Test 2: Disable VPN
```
Expected:
- "Turn off" button changes to "Turning off..."
- After 1-2 seconds: "Turn on" button appears
- Status shows "VPN is OFF"
- Button returns to normal color

Action:
1. VPN is already ON (from Test 1)
2. Click "Turn off" button
3. Wait for disconnection
4. Verify status changes
```

### Test 3: Toggle VPN Multiple Times
```
Expected:
- VPN toggles on/off smoothly
- Status updates correctly
- No errors in console

Action:
1. Click "Turn on"
2. Wait for connection
3. Click "Turn off"
4. Wait for disconnection
5. Repeat 3 times
6. Verify smooth operation
```

---

## ✅ Test Threat Detection Accuracy

### Test Malicious URLs
```
✅ https://tiktok-free-download.com
   Expected: MALICIOUS (Prize Scam)

✅ https://secure-login-verify.com
   Expected: MALICIOUS (Banking Phishing)

✅ https://claim-your-prize-now.com
   Expected: MALICIOUS (Prize Scam)

✅ https://verify-paypal-account.com
   Expected: MALICIOUS (Phishing)

✅ https://update-windows-defender.com
   Expected: MALICIOUS (Fake Antivirus)
```

### Test Safe URLs
```
✅ https://google.com
   Expected: SAFE

✅ https://amazon.com
   Expected: SAFE

✅ https://github.com
   Expected: SAFE

✅ https://stackoverflow.com
   Expected: SAFE
```

### Test Suspicious URLs
```
✅ https://example-banking.xyz
   Expected: SUSPICIOUS (Medium risk)

✅ https://free-download-site.top
   Expected: SUSPICIOUS (Medium risk)
```

---

## ✅ Test Real-Time Updates

### Test 1: Stats Auto-Update
```
Expected:
- Stats update every 5 seconds
- No manual refresh needed
- Smooth animation

Action:
1. Open dashboard
2. Leave it open for 30 seconds
3. Watch stats update automatically
4. Verify no manual action needed
```

### Test 2: Threat Feed Auto-Update
```
Expected:
- New threats appear automatically
- No manual refresh needed
- Animated slide-in effect

Action:
1. Open dashboard
2. Scan multiple URLs
3. Verify threats appear in feed
4. Verify no manual refresh needed
```

### Test 3: VPN Status Auto-Update
```
Expected:
- VPN status updates automatically
- Shows current connection state
- Updates when VPN changes

Action:
1. Open dashboard
2. Toggle VPN on/off
3. Verify status updates automatically
```

---

## ✅ Test Data Persistence

### Test 1: Threat History Persists
```
Expected:
- Threats saved to storage
- Threats appear after reload
- History limited to 100 items

Action:
1. Open dashboard
2. Scan a URL (threat detected)
3. Close dashboard
4. Reopen dashboard
5. Verify threat still in feed
```

### Test 2: Stats Persist
```
Expected:
- Stats saved to storage
- Stats appear after reload
- Values preserved

Action:
1. Open dashboard
2. Note the stats values
3. Close dashboard
4. Reopen dashboard
5. Verify stats values same
```

---

## ✅ Test Error Handling

### Test 1: Invalid URL
```
Expected:
- Scanner handles gracefully
- Shows error message
- No crash

Action:
1. Open dashboard
2. Paste invalid URL: "not a url"
3. Click "Scan now"
4. Verify error handled
```

### Test 2: Empty Input
```
Expected:
- Scanner requires input
- Shows message or focuses input
- No crash

Action:
1. Open dashboard
2. Leave scanner empty
3. Click "Scan now"
4. Verify error handled
```

### Test 3: Network Error
```
Expected:
- VPN handles errors gracefully
- Shows error message
- No crash

Action:
1. Open dashboard
2. Try to enable VPN
3. If error occurs, verify handled
```

---

## ✅ Test Browser Console

### Check for Errors
```
1. Open dashboard
2. Press F12 (Developer Tools)
3. Go to Console tab
4. Look for red error messages
5. Should see NO red errors

Expected:
- No red error messages
- May see info/warning messages (OK)
```

### Check for Warnings
```
1. Open dashboard
2. Press F12 (Developer Tools)
3. Go to Console tab
4. Look for yellow warning messages
5. Warnings are OK, errors are not
```

---

## ✅ Test Performance

### Test 1: Memory Usage
```
Expected:
- Dashboard uses 2-5 MB
- No memory leaks
- Smooth operation

Action:
1. Open dashboard
2. Press F12 (Developer Tools)
3. Go to Memory tab
4. Take heap snapshot
5. Verify reasonable memory usage
```

### Test 2: CPU Usage
```
Expected:
- CPU usage <1% idle
- Smooth animations
- No lag

Action:
1. Open dashboard
2. Watch for smooth operation
3. Verify no lag or stuttering
```

### Test 3: Scan Speed
```
Expected:
- Scan completes in <500ms
- Fast analysis
- Instant results

Action:
1. Open dashboard
2. Scan a URL
3. Verify quick result
```

---

## ✅ Test UI/UX

### Test 1: Animations
```
Expected:
- Smooth animations
- Threat slide-in effect
- Stats pulse effect
- No stuttering

Action:
1. Open dashboard
2. Scan URL (watch threat appear)
3. Watch stats update
4. Verify smooth animations
```

### Test 2: Responsive Design
```
Expected:
- Dashboard looks good
- All elements visible
- No overlapping text
- Buttons clickable

Action:
1. Open dashboard
2. Check layout
3. Verify all elements visible
4. Try clicking buttons
```

### Test 3: Color Coding
```
Expected:
- Malicious threats: Red
- Suspicious threats: Amber
- Safe content: Green
- Clear visual distinction

Action:
1. Open dashboard
2. Scan different threat types
3. Verify color coding
```

---

## 📋 Final Checklist

- [ ] Extension loads without errors
- [ ] Dashboard opens without errors
- [ ] Stats display correctly
- [ ] Stats update every 5 seconds
- [ ] Threat feed displays
- [ ] Threats appear in feed
- [ ] Protection status displays
- [ ] Scanner works for URLs
- [ ] Scanner works for text
- [ ] Malicious URLs detected
- [ ] Safe URLs pass
- [ ] VPN can be enabled
- [ ] VPN can be disabled
- [ ] VPN status updates
- [ ] Threat history persists
- [ ] Stats persist
- [ ] No console errors
- [ ] Smooth animations
- [ ] Fast scan speed
- [ ] All buttons clickable

---

## 🎉 If All Tests Pass

✅ **Extension is working perfectly!**

You can now:
1. Use the advanced threat scanner
2. Browse privately with VPN
3. Monitor real-time protection
4. Check threat history
5. View protection stats

---

## ❌ If Tests Fail

### Common Issues & Solutions

**Issue**: Dashboard doesn't load
```
Solution:
1. Reload extension (F5 or refresh button)
2. Clear cache (chrome://extensions/ → Clear data)
3. Check console for errors (F12)
```

**Issue**: Stats don't update
```
Solution:
1. Check if background service is running
2. Reload extension
3. Check console for errors
```

**Issue**: Scanner doesn't work
```
Solution:
1. Check if threat-detector.js is loaded
2. Reload extension
3. Check console for errors
```

**Issue**: VPN doesn't work
```
Solution:
1. Check if vpn-manager.js is loaded
2. Reload extension
3. Check console for errors
```

---

## 📞 Report Issues

If you find any issues:
1. Note the exact error message
2. Check browser console (F12)
3. Take a screenshot
4. Report with details

---

**Testing Guide Complete!**
**Version**: 2.0.1
**Date**: May 9, 2026
**Status**: ✅ Ready to Test
