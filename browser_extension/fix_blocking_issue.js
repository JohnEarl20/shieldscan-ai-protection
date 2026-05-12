// Fix for blocking legitimate websites
// This script ensures VPN is disabled and proxy settings are reset

console.log('🔧 Fixing blocking issues...');

// Disable VPN and reset proxy
if (typeof chrome !== 'undefined' && chrome.proxy) {
  chrome.proxy.settings.set(
    { value: { mode: 'direct' }, scope: 'regular' },
    () => {
      if (chrome.runtime.lastError) {
        console.error('Proxy reset error:', chrome.runtime.lastError);
      } else {
        console.log('✅ Proxy reset to direct connection');
      }
    }
  );
}

// Reset storage to ensure VPN is disabled
if (typeof chrome !== 'undefined' && chrome.storage) {
  chrome.storage.local.get(['vpnEnabled'], (result) => {
    if (result.vpnEnabled) {
      chrome.storage.local.set({ vpnEnabled: false }, () => {
        console.log('✅ VPN disabled in storage');
      });
    }
  });
}

// Add legitimate sites to allowlist
const legitimateSites = [
  'facebook.com',
  'www.facebook.com',
  'm.facebook.com',
  'google.com',
  'www.google.com',
  'youtube.com',
  'www.youtube.com',
  'microsoft.com',
  'github.com',
  'stackoverflow.com',
  'amazon.com',
  'netflix.com',
  'twitter.com',
  'instagram.com',
  'linkedin.com',
  'reddit.com',
  'wikipedia.org'
];

if (typeof chrome !== 'undefined' && chrome.storage) {
  chrome.storage.local.get(['allowlist'], (result) => {
    const currentAllowlist = result.allowlist || [];
    const updatedAllowlist = [...new Set([...currentAllowlist, ...legitimateSites])];
    
    chrome.storage.local.set({ allowlist: updatedAllowlist }, () => {
      console.log('✅ Updated allowlist with legitimate sites');
      console.log('Allowlist now includes:', updatedAllowlist);
    });
  });
}

console.log('🎉 Blocking issues should now be fixed!');