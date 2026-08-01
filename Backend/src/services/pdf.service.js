const puppeteer = require("puppeteer")
const sanitizeHtml = require("sanitize-html")

const SET_CONTENT_TIMEOUT_MS = 15000
const PDF_TIMEOUT_MS = 20000
const PROTOCOL_TIMEOUT_MS = 30000

// A headless Chromium is ~100MB resident. On a 512MB instance, letting every
// request render at once is an OOM waiting to happen.
const MAX_CONCURRENT_RENDERS = 2

let browserPromise = null
let activeRenders = 0
const renderQueue = []

/**
 * Launches Chromium once and reuses it. The previous implementation launched a
 * full browser per request and leaked the process whenever rendering threw.
 */
async function getBrowser() {
    if (browserPromise) {
        const existing = await browserPromise.catch(() => null)
        if (existing && existing.connected) return existing
        browserPromise = null
    }

    browserPromise = puppeteer.launch({
        headless: true,
        protocolTimeout: PROTOCOL_TIMEOUT_MS,
        args: [
            "--no-sandbox",
            "--disable-setuid-sandbox",
            "--disable-dev-shm-usage",
            "--disable-accelerated-2d-canvas",
            "--no-first-run",
            "--disable-gpu"
        ]
    })

    const browser = await browserPromise
    // If Chromium dies (OOM kill, crash), drop the handle so the next call
    // relaunches instead of failing forever against a dead connection.
    browser.once("disconnected", () => { browserPromise = null })
    return browser
}

async function closeBrowser() {
    const browser = await (browserPromise || Promise.resolve(null)).catch(() => null)
    browserPromise = null
    if (browser) await browser.close().catch(() => {})
}

function acquireRenderSlot() {
    if (activeRenders < MAX_CONCURRENT_RENDERS) {
        activeRenders += 1
        return Promise.resolve()
    }
    return new Promise((resolve) => renderQueue.push(resolve))
}

function releaseRenderSlot() {
    const next = renderQueue.shift()
    if (next) return next()
    activeRenders -= 1
}

/**
 * The HTML fed to the renderer is written by an LLM whose input includes a
 * user-supplied job description, so it is treated as untrusted: scripts, remote
 * resources, event handlers and javascript: URLs are all removed.
 */
function sanitizeResumeHtml(html) {
    return sanitizeHtml(String(html || ""), {
        allowedTags: sanitizeHtml.defaults.allowedTags.concat([
            "style", "h1", "h2", "header", "footer", "section", "article",
            "span", "small", "hr", "img"
        ]),
        // Drop the *contents* of these, not just the tags.
        nonTextTags: ["script", "noscript", "textarea", "option", "iframe", "object", "embed"],
        allowedAttributes: {
            "*": ["style", "class", "id"],
            a: ["href"],
            img: ["src", "alt", "width", "height"]
        },
        // mailto/tel for contact lines; data: for inline images. No http(s),
        // so nothing can reference a remote host.
        allowedSchemes: ["mailto", "tel", "data"],
        allowedSchemesAppliedToAttributes: ["href", "src"],
        allowVulnerableTags: true // <style> is intentionally allowed for layout
    })
}

/**
 * Wraps the sanitized fragment in a document with a locked-down CSP and print
 * defaults, so page geometry does not depend on whatever the model emitted.
 */
function buildPrintDocument(bodyHtml) {
    return `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src 'none'">
<style>
  @page { size: A4; margin: 16mm 14mm; }
  html, body { margin: 0; padding: 0; }
  body {
    font-family: Georgia, 'Times New Roman', Times, serif;
    font-size: 10.5pt;
    line-height: 1.4;
    color: #111;
    -webkit-print-color-adjust: exact;
    print-color-adjust: exact;
  }
  h1, h2, h3, h4 { break-after: avoid; page-break-after: avoid; }
  li, tr, section, header { break-inside: avoid; page-break-inside: avoid; }
  a { color: inherit; text-decoration: none; }
  table { width: 100%; border-collapse: collapse; }
</style>
</head>
<body>${bodyHtml}</body>
</html>`
}

/**
 * Renders HTML to a PDF buffer inside a hardened page: no JavaScript, and every
 * network request aborted so the renderer cannot be used to reach internal
 * services via injected markup.
 */
async function generatePdfFromHtml(htmlContent) {
    const document = buildPrintDocument(sanitizeResumeHtml(htmlContent))

    await acquireRenderSlot()

    let page
    try {
        const browser = await getBrowser()
        page = await browser.newPage()

        await page.setJavaScriptEnabled(false)

        await page.setRequestInterception(true)
        page.on("request", (request) => {
            const url = request.url()
            // about: is the blank document setContent navigates to; data: is inline.
            if (url.startsWith("about:") || url.startsWith("data:")) return request.continue()
            request.abort().catch(() => {})
        })

        await page.emulateMediaType("print")
        await page.setContent(document, {
            waitUntil: "domcontentloaded",
            timeout: SET_CONTENT_TIMEOUT_MS
        })

        return await page.pdf({
            format: "A4",
            printBackground: true,
            timeout: PDF_TIMEOUT_MS,
            margin: { top: "16mm", bottom: "16mm", left: "14mm", right: "14mm" }
        })
    } finally {
        // Always runs, so a render failure cannot leak a page or a slot.
        if (page) await page.close().catch(() => {})
        releaseRenderSlot()
    }
}

module.exports = { generatePdfFromHtml, sanitizeResumeHtml, closeBrowser }
