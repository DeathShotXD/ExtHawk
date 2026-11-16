// Patched build: no external message bridge, no cookies, no scripting,
// no host access, and no page-supplied URLs.
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({ installed: Date.now() });
});
