let db = null;

async function getDb() {
    if (db) {
        return db;
    } else {
        return await new Promise((rs, rj) => {
            const req = indexedDB.open("http_mock", 1);
            req.onsuccess = (event) => rs(event.target.result);
            req.onerror = rj;
            req.onupgradeneeded = (event) => {
                db = event.target.result;
                db.createObjectStore("mocks", { keyPath: "nonce" });
            };
        })
    }
}

async function setMock(mock) {
    const db = await getDb();
    await new Promise((rs, rj) => {
        const transaction = db.transaction("mocks", "readwrite");
        transaction.oncomplete = rs;
        transaction.onerror = rj;
        const store = transaction.objectStore("mocks");
        store.put(mock);
    })
}

async function getMock(nonce) {
    const db = await getDb();
    return await new Promise((rs, rj) => {
        const req = db.transaction("mocks")
            .objectStore("mocks")
            .get(nonce);
        req.onsuccess = (event) => rs(event.target.result);
        req.onerror = rj;
    });
}

self.addEventListener("fetch", (event) => {
    event.respondWith((async () => {
        try {
            const request = event.request;
            const url = new URL(request.url);
            if (url.host === "mock_configure") {
                const { method, path, status_code, nonce, body, headers } = await request.json();
                await setMock({ method, path, status_code, nonce, body, headers, hits: 0 });
                return new Response(null, { status: 204 });
            } else if (url.host === "mock_assert") {
                const nonce = url.pathname.substring(1);
                const { hits } = await getMock(nonce);
                return new Response(hits, { status: 200 });
            } else {
                const nonce = url.host.split('_')[1];
                const { method, path, status_code, body, headers, hits } = await getMock(nonce);
                if (request.method !== method) {
                    return new Response(`expected ${method}, got ${request.method}`, { status: 405 });
                }
                if (url.pathname !== path) {
                    return new Response(`expcted ${path}, got ${url.pathname}`, { status: 404 });
                }
                await setMock({ method, path, status_code, nonce, body, headers, hits: hits + 1 });
                return new Response(Uint8Array.from(body), { status: status_code, headers });
            }
        } catch (e) {
            return new Response(e.toString(), { status: 503 });
        }
    })())
});

self.addEventListener("activate", (event) => {
    skipWaiting();
    event.waitUntil(clients.claim());
});
