const API_BASE = 'http://127.0.0.1:5000';
let lastSeenAttackCount = 0;

// Setup alarms for background heartbeat
chrome.runtime.onInstalled.addListener(() => {
  chrome.alarms.create('sentinelHeartbeat', { periodInMinutes: 0.1 });
  updateBadgeStatus();
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'sentinelHeartbeat') {
    updateBadgeStatus();
  }
});

// Update Badge Status & Check for Threat Notifications
async function updateBadgeStatus() {
  try {
    const res = await fetch(`${API_BASE}/api/status`);
    if (!res.ok) throw new Error('Offline');
    const data = await res.json();

    const attackCount = data.attack_flows || 0;
    const riskLevel = data.risk_level || 'SAFE';

    // Set badge text
    if (attackCount > 0) {
      chrome.action.setBadgeText({ text: attackCount > 999 ? '999+' : String(attackCount) });
    } else {
      chrome.action.setBadgeText({ text: 'OK' });
    }

    // Set badge background color based on threat level
    if (riskLevel === 'CRITICAL') {
      chrome.action.setBadgeBackgroundColor({ color: '#ef4444' });
    } else if (riskLevel === 'ELEVATED') {
      chrome.action.setBadgeBackgroundColor({ color: '#f59e0b' });
    } else {
      chrome.action.setBadgeBackgroundColor({ color: '#10b981' });
    }

    // Trigger Notification on new attack detection
    if (attackCount > lastSeenAttackCount && lastSeenAttackCount !== 0) {
      const diff = attackCount - lastSeenAttackCount;
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon128.png',
        title: '🚨 Sentinel AI Security Alert',
        message: `Detected ${diff} new network threat flow(s)! Current Risk Level: ${riskLevel}`,
        priority: 2
      });
    }
    lastSeenAttackCount = attackCount;

  } catch (err) {
    chrome.action.setBadgeText({ text: 'OFF' });
    chrome.action.setBadgeBackgroundColor({ color: '#6b7280' });
  }
}
