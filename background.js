const jwtRegex = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/;

async function checkJWT(tabId, url) {
    const cookies = await browser.cookies.getAll({ url });
    const jwtCookie = cookies.find(c => jwtRegex.test(c.value));
    const key = `jwt:${tabId}`;

    if (jwtCookie) {
        await browser.storage.local.set({ [key]: jwtCookie.value });
        browser.browserAction.setBadgeText({ tabId, text: 'JWT' });
        browser.browserAction.setBadgeBackgroundColor({ tabId, color: '#c62828' });
        browser.browserAction.setTitle({
            tabId,
            title: `JWT found in cookie: ${jwtCookie.name}`
        });
    } else {
        await browser.storage.local.remove(key);
        browser.browserAction.setBadgeText({ tabId, text: '' });
        browser.browserAction.setTitle({ tabId, title: 'JWT Decoder' });
    }
}

// Runs on every page load
browser.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url?.startsWith('http')) {
        checkJWT(tabId, tab.url);
    }
});

// Clean up when a tab closes
browser.tabs.onRemoved.addListener(tabId => {
    browser.storage.local.remove(`jwt:${tabId}`);
});