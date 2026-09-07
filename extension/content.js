// Sentinel AI Web Page Content Inspector
console.log('[Sentinel AI] Network Security Inspection Active on:', window.location.hostname);

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'getPageSecurity') {
    sendResponse({
      domain: window.location.hostname,
      protocol: window.location.protocol,
      isSecure: window.location.protocol === 'https:'
    });
  }
});
