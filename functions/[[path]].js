// CONFIG_START
const UPSTREAM_PRIMARY = 'https://bu0eg1tdzu.cloudflare-gateway.com/dns-query';
const UPSTREAM_FALLBACK = 'https://rhpcv957tj.cloudflare-gateway.com/dns-query';
const UPSTREAM_GEO_BYPASS = 'https://dns.mullvad.net/dns-query'; // Re-resolve when geo-block returns loopback
const UPSTREAM_TIMEOUT = 5000;

// Refresh interval for ALL lists (blocklist, allowlists, private TLDs, redirect rules)
const ALL_LISTS_REFRESH_INTERVAL = 3600000; // 1 hour

const AD_BLOCK_ENABLED = true;
const BLOCKLIST_URL = 'https://doh.sonn.qzz.io/rules/blocklists.txt';
const ALLOWLIST_URL = 'https://doh.sonn.qzz.io/rules/allowlists.txt';

const ECS_INJECTION_ENABLED = true;
const ECS_PREFIX_V4 = 24;
const ECS_PREFIX_V6 = 48;

// Block query types early to save Cloudflare Pages requests
const BLOCK_ANY = false;    // TYPE 255 — ANY queries
const BLOCK_AAAA = false;   // TYPE 28  — IPv6 queries
const BLOCK_PTR = false;    // TYPE 12  — Reverse DNS
const BLOCK_HTTPS = false;  // TYPE 65  — HTTPS record queries

// Block private/internal TLDs and router domains
const BLOCK_PRIVATE_TLD = true;
const PRIVATE_TLD_URL = 'https://doh.sonn.qzz.io/rules/private_tlds.txt';

// DNS redirect/rewrite (local CNAME overrides)
const DNS_REDIRECT_ENABLED = true;
const REDIRECT_RULES_URL = 'https://doh.sonn.qzz.io/rules/redirect_rules.txt';

// Dedicated Mullvad Upstream Domains
const MULLVAD_UPSTREAM_ENABLED = true;
const MULLVAD_UPSTREAM_URL = 'https://doh.sonn.qzz.io/rules/mullvad_upstream.txt';

// CONFIG_END

// Pre-compiled regex patterns for performance
const IPV4_MAPPED_REGEX = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i;
const IPV6_VALID_REGEX = /^[0-9a-f:]+$/i;
const IPV6_GROUP_REGEX = /^[0-9a-f]+$/i;
const IPV4_REGEX = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV6_FULL_REGEX = /^([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])$/;

function isValidIP(ip) {
    return IPV4_REGEX.test(ip) || IPV6_FULL_REGEX.test(ip);
}

function ipToReverseDomain(ip) {
    if (ip.includes(':')) {
        // IPv6
        let expanded = ip;
        if (ip.includes('::')) {
            const [head, tail] = ip.split('::');
            const headParts = head ? head.split(':') : [];
            const tailParts = tail ? tail.split(':') : [];
            const missing = 8 - (headParts.length + tailParts.length);
            expanded = headParts.concat(Array(missing).fill('0')).concat(tailParts).join(':');
        } else {
            const parts = ip.split(':');
            if (parts.length < 8) {
                expanded = parts.concat(Array(8 - parts.length).fill('0')).join(':');
            }
        }
        const parts = expanded.split(':').map(p => p.padStart(4, '0'));
        return parts.join('').split('').reverse().join('.') + '.ip6.arpa';
    } else {
        // IPv4
        return ip.split('.').reverse().join('.') + '.in-addr.arpa';
    }
}

// ==================== STATE ====================
let adBlocklist = new Set();
let adAllowlist = new Set();
let privateTlds = new Set();
let redirectRules = new Map(); // domain → target domain
let mullvadUpstreamDomains = new Set();
let blocklistLastFetch = 0;
let blocklistPromise = null;
let blocklistsFetched = false; // Track if lists have been fetched at least once

// ==================== AD BLOCK ====================
async function fetchList(url) {
    try {
        const res = await fetch(url, { signal: AbortSignal.timeout(15000) });
        if (!res.ok) return new Set();
        const text = await res.text();
        const domains = new Set();
        for (const line of text.split('\n')) {
            const d = line.trim();
            if (d && !d.startsWith('#') && !d.startsWith('!')) domains.add(d);
        }
        return domains;
    } catch { return new Set(); }
}

async function fetchRedirectRules(url) {
    try {
        const res = await fetch(url, { signal: AbortSignal.timeout(15000) });
        if (!res.ok) return new Map();
        const text = await res.text();
        const rules = new Map();
        for (const line of text.split('\n')) {
            const d = line.trim();
            if (!d || d.startsWith('#') || d.startsWith('!')) continue;
            const parts = d.split(/\s+/);
            if (parts.length === 2) rules.set(parts[0].toLowerCase(), parts[1].toLowerCase());
        }
        return rules;
    } catch { return new Map(); }
}

async function refreshBlocklists(baseUrl) {
    if (blocklistsFetched && Date.now() - blocklistLastFetch < ALL_LISTS_REFRESH_INTERVAL) return;
    if (blocklistPromise) return blocklistPromise;

    blocklistPromise = (async () => {
        try {
            const bUrl = new URL(BLOCKLIST_URL, baseUrl).toString();
            const aUrl = new URL(ALLOWLIST_URL, baseUrl).toString();
            const pUrl = new URL(PRIVATE_TLD_URL, baseUrl).toString();
            const rUrl = new URL(REDIRECT_RULES_URL, baseUrl).toString();
            const mUrl = new URL(MULLVAD_UPSTREAM_URL, baseUrl).toString();

            const [block, allow, privateList, redirRules, mullvadList] = await Promise.all([
                AD_BLOCK_ENABLED ? fetchList(bUrl) : Promise.resolve(new Set()),
                AD_BLOCK_ENABLED ? fetchList(aUrl) : Promise.resolve(new Set()),
                BLOCK_PRIVATE_TLD ? fetchList(pUrl) : Promise.resolve(new Set()),
                DNS_REDIRECT_ENABLED ? fetchRedirectRules(rUrl) : Promise.resolve(new Map()),
                MULLVAD_UPSTREAM_ENABLED ? fetchList(mUrl) : Promise.resolve(new Set())
            ]);

            if (AD_BLOCK_ENABLED) { adBlocklist = block; adAllowlist = allow; }
            if (BLOCK_PRIVATE_TLD) { privateTlds = privateList; }
            if (DNS_REDIRECT_ENABLED) { redirectRules = redirRules; }
            if (MULLVAD_UPSTREAM_ENABLED) { mullvadUpstreamDomains = mullvadList; }

            blocklistLastFetch = Date.now();
            blocklistsFetched = true;
        } finally { blocklistPromise = null; }
    })();

    return blocklistPromise;
}

// Extract QTYPE from first question section
function extractQtype(buf) {
    try {
        const v = new Uint8Array(buf);
        if (v.length < 12) return null;
        const qd = (v[4] << 8) | v[5];
        if (qd === 0) return null;
        let off = 12;
        while (off < v.length) {
            const len = v[off];
            if (len === 0) { off++; break; }
            if ((len & 0xC0) === 0xC0) { off += 2; break; }
            off += len + 1;
        }
        if (off + 2 > v.length) return null;
        return (v[off] << 8) | v[off + 1];
    } catch { return null; }
}

// Build set of blocked query types from config
function getBlockedQtypes() {
    const blocked = new Set();
    if (BLOCK_ANY) blocked.add(255);
    if (BLOCK_AAAA) blocked.add(28);
    if (BLOCK_PTR) blocked.add(12);
    if (BLOCK_HTTPS) blocked.add(65);
    return blocked;
}
const BLOCKED_QTYPES = getBlockedQtypes();

// Parse all question domains
function extractAllDomains(buf) {
    const domains = [];
    try {
        const v = new Uint8Array(buf);
        if (v.length < 12) return domains;
        const qd = (v[4] << 8) | v[5];
        if (qd === 0) return domains;
        let off = 12;
        for (let q = 0; q < qd; q++) {
            const labels = [];
            while (off < v.length) {
                const len = v[off];
                if (len === 0) { off++; break; }
                if ((len & 0xC0) === 0xC0) { off += 2; break; }
                off++;
                if (off + len > v.length) return domains;
                let label = '';
                for (let i = 0; i < len; i++) label += String.fromCharCode(v[off + i]);
                labels.push(label);
                off += len;
            }
            off += 4; // QTYPE + QCLASS
            if (labels.length > 0) domains.push(labels.join('.').toLowerCase());
        }
    } catch { }
    return domains;
}

function hasLoopbackInAnswer(buf) {
    try {
        const v = new Uint8Array(buf);
        if (v.length < 12) return false;
        const qd = (v[4] << 8) | v[5];
        const an = (v[6] << 8) | v[7];
        if (an === 0) return false;

        let off = 12;
        for (let i = 0; i < qd; i++) {
            while (off < v.length) {
                const len = v[off];
                if (len === 0) { off++; break; }
                if ((len & 0xC0) === 0xC0) { off += 2; break; }
                off += len + 1;
            }
            off += 4;
        }

        for (let i = 0; i < an; i++) {
            while (off < v.length) {
                const len = v[off];
                if (len === 0) { off++; break; }
                if ((len & 0xC0) === 0xC0) { off += 2; break; }
                off += len + 1;
            }
            if (off + 10 > v.length) break;
            const type = (v[off] << 8) | v[off + 1];
            const cls = (v[off + 2] << 8) | v[off + 3];
            const rdlen = (v[off + 8] << 8) | v[off + 9];
            off += 10;
            if (type === 1 && cls === 1 && rdlen === 4) {
                if (v[off] === 127 && v[off + 1] === 0 && v[off + 2] === 0 && v[off + 3] === 1) return true;
            }
            off += rdlen;
        }
    } catch { }
    return false;
}

function isDomainBlocked(domain) {
    if (!domain || adBlocklist.size === 0) return false;
    if (adAllowlist.has(domain)) return false;
    if (adBlocklist.has(domain)) return true;
    return false;
}

function isDomainPrivate(domain) {
    if (!domain || privateTlds.size === 0) return false;
    if (privateTlds.has(domain)) return true;
    let pos = 0;
    while ((pos = domain.indexOf('.', pos)) !== -1) {
        if (privateTlds.has(domain.substring(pos + 1))) return true;
        pos++;
    }
    return false;
}

function isMullvadDomain(domain) {
    if (!domain || mullvadUpstreamDomains.size === 0) return false;
    if (mullvadUpstreamDomains.has(domain)) return true;
    let pos = 0;
    while ((pos = domain.indexOf('.', pos)) !== -1) {
        if (mullvadUpstreamDomains.has(domain.substring(pos + 1))) return true;
        pos++;
    }
    return false;
}

// Convert binary DNS response to JSON format with support for common record types
function dnsResponseToJson(buffer) {
    const v = new Uint8Array(buffer);
    if (v.length < 12) return { Status: 2, Comment: "Invalid response" };
    const res = {
        Status: v[3] & 0x0F,
        TC: !!(v[2] & 0x02),
        RD: !!(v[2] & 0x01),
        RA: !!(v[3] & 0x80),
        AD: !!(v[3] & 0x20),
        CD: !!(v[3] & 0x10),
        Question: [],
        Answer: [],
        Authority: [],
        Additional: []
    };
    let off = 12;

    const parseName = () => {
        let labels = [];
        let curr = off;
        let jumped = false;
        let depth = 0;

        while (depth < 20 && curr < v.length) {
            const b = v[curr];
            if (b === 0) {
                if (!jumped) off = curr + 1;
                curr++;
                break;
            }
            if ((b & 0xC0) === 0xC0) {
                if (curr + 1 >= v.length) break;
                const ptr = ((b & 0x3F) << 8) | v[curr + 1];
                if (!jumped) off = curr + 2;
                jumped = true;
                curr = ptr;
                depth++;
            } else {
                const l = v[curr++];
                if (curr + l > v.length) break;
                let label = "";
                for (let i = 0; i < l; i++) label += String.fromCharCode(v[curr++]);
                labels.push(label);
            }
        }
        if (!jumped && off < curr) off = curr;
        return labels.length === 0 ? "." : labels.join('.');
    };

    // Helper: add trailing dot — only if name is not root "."
    const fqdn = (name) => name === '.' ? name : name + '.';

    // Helper: bytes slice → uppercase hex string
    const toHex = (from, to) =>
        Array.from(v.slice(from, to)).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();

    // Helper: bytes slice → base64 string
    const toB64 = (from, to) => btoa(String.fromCharCode(...v.slice(from, to)));

    // Helper: Compress IPv6 address (replace longest run of zeros with ::)
    const compressIPv6 = (ip) => {
        const segments = ip.split(':');
        let maxStart = -1, maxLen = 0, currStart = -1, currLen = 0;
        for (let i = 0; i < segments.length; i++) {
            if (segments[i] === '0') {
                if (currStart === -1) currStart = i;
                currLen++;
                if (currLen > maxLen) { maxStart = currStart; maxLen = currLen; }
            } else { currStart = -1; currLen = 0; }
        }
        if (maxLen > 1) {
            const left = segments.slice(0, maxStart).join(':');
            const right = segments.slice(maxStart + maxLen).join(':');
            return `${left}::${right}`;
        }
        return ip;
    };

    const TYPE_NAMES = {
        1:'A', 2:'NS', 5:'CNAME', 6:'SOA', 12:'PTR', 13:'HINFO', 15:'MX', 16:'TXT', 17:'RP', 18:'AFSDB',
        24:'SIG', 25:'KEY', 28:'AAAA', 29:'LOC', 33:'SRV', 35:'NAPTR', 37:'CERT', 39:'DNAME', 43:'DS',
        44:'SSHFP', 45:'IPSECKEY', 46:'RRSIG', 47:'NSEC', 48:'DNSKEY', 52:'TLSA', 59:'CDS', 60:'CDNSKEY',
        64:'SVCB', 65:'HTTPS', 99:'SPF', 256:'URI', 257:'CAA'
    };

    const parseRdata = (type, len) => {
        const start = off;
        let d = "";
        try {
            if (type === 1 && len === 4) { // A
                d = `${v[off]}.${v[off+1]}.${v[off+2]}.${v[off+3]}`;

            } else if (type === 28 && len === 16) { // AAAA
                const p = []; for (let j=0; j<8; j++) p.push(((v[off+j*2]<<8)|v[off+j*2+1]).toString(16));
                d = compressIPv6(p.join(":"));

            } else if (type === 5 || type === 2 || type === 12 || type === 39) { // CNAME, NS, PTR, DNAME
                d = fqdn(parseName());

            } else if (type === 17) { // RP
                const mbox = parseName(); const txt = parseName();
                d = `${fqdn(mbox)} ${fqdn(txt)}`;

            } else if (type === 13) { // HINFO
                let hOff = off; const cpuLen = v[hOff++]; let cpu = ""; for (let j=0; j<cpuLen; j++) cpu += String.fromCharCode(v[hOff++]);
                const osLen = v[hOff++]; let os = ""; for (let j=0; j<osLen; j++) os += String.fromCharCode(v[hOff++]);
                d = `"${cpu}" "${os}"`;

            } else if (type === 15) { // MX
                const pref = (v[off] << 8) | v[off+1];
                off += 2;
                d = `${pref} ${fqdn(parseName())}`;

            } else if (type === 33) { // SRV
                const prio = (v[off] << 8) | v[off+1]; const weight = (v[off+2] << 8) | v[off+3]; const port = (v[off+4] << 8) | v[off+5];
                off += 6;
                d = `${prio} ${weight} ${port} ${fqdn(parseName())}`;

            } else if (type === 16 || type === 99) { // TXT, SPF
                let txt = "", tOff = off;
                while (tOff < start + len) { const l = v[tOff++]; for (let j=0; j<l; j++) txt += String.fromCharCode(v[tOff++]); }
                d = txt;

            } else if (type === 6) { // SOA
                const mname = parseName(); const rname = parseName();
                const serial = ((v[off]<<24|v[off+1]<<16|v[off+2]<<8|v[off+3])>>>0); off += 4;
                const refresh = ((v[off]<<24|v[off+1]<<16|v[off+2]<<8|v[off+3])>>>0); off += 4;
                const retry = ((v[off]<<24|v[off+1]<<16|v[off+2]<<8|v[off+3])>>>0); off += 4;
                const expire = ((v[off]<<24|v[off+1]<<16|v[off+2]<<8|v[off+3])>>>0); off += 4;
                const min = ((v[off]<<24|v[off+1]<<16|v[off+2]<<8|v[off+3])>>>0);
                d = `${fqdn(mname)} ${fqdn(rname)} ${serial} ${refresh} ${retry} ${expire} ${min}`;

            } else if (type === 35) { // NAPTR
                const order = (v[off]<<8)|v[off+1]; const pref = (v[off+2]<<8)|v[off+3]; let nOff = off+4;
                const fLen = v[nOff++]; let f = ""; for(let j=0; j<fLen; j++) f += String.fromCharCode(v[nOff++]);
                const sLen = v[nOff++]; let s = ""; for(let j=0; j<sLen; j++) s += String.fromCharCode(v[nOff++]);
                const rLen = v[nOff++]; let re = ""; for(let j=0; j<rLen; j++) re += String.fromCharCode(v[nOff++]);
                off = nOff;
                d = `${order} ${pref} "${f}" "${s}" "${re}" ${fqdn(parseName())}`;

            } else if (type === 44) { // SSHFP
                d = `${v[off]} ${v[off+1]} ${toHex(off+2, start+len)}`;

            } else if (type === 43 || type === 59) { // DS, CDS
                const kt = (v[off]<<8)|v[off+1]; d = `${kt} ${v[off+2]} ${v[off+3]} ${toHex(off+4, start+len)}`;

            } else if (type === 48 || type === 60 || type === 25) { // DNSKEY, CDNSKEY, KEY
                const f = (v[off]<<8)|v[off+1]; d = `${f} ${v[off+2]} ${v[off+3]} ${toB64(off+4, start+len)}`;

            } else if (type === 52) { // TLSA
                d = `${v[off]} ${v[off+1]} ${v[off+2]} ${toHex(off+3, start+len)}`;

            } else if (type === 37) { // CERT
                const ct = (v[off]<<8)|v[off+1]; const kt = (v[off+2]<<8)|v[off+3]; d = `${ct} ${kt} ${v[off+4]} ${toB64(off+5, start+len)}`;

            } else if (type === 46 || type === 24) { // RRSIG, SIG
                const tc = (v[off]<<8)|v[off+1]; const al = v[off+2]; const lb = v[off+3];
                const ottl = ((v[off+4]<<24|v[off+5]<<16|v[off+6]<<8|v[off+7])>>>0);
                const exp = ((v[off+8]<<24|v[off+9]<<16|v[off+10]<<8|v[off+11])>>>0);
                const inc = ((v[off+12]<<24|v[off+13]<<16|v[off+14]<<8|v[off+15])>>>0);
                const kt = (v[off+16]<<8)|v[off+17]; off += 18;
                const sgn = parseName(); const sig = toB64(off, start+len);
                d = `${tc} ${al} ${lb} ${ottl} ${exp} ${inc} ${kt} ${fqdn(sgn)} ${sig}`;

            } else if (type === 47) { // NSEC
                let name = parseName();
                if (name.includes('\u0000')) name = name.replace(/\u0000/g, '\\000');
                const ts = [];
                while (off < start + len) {
                    const wb = v[off++]; const bl = v[off++];
                    for (let i=0; i<bl && off<start+len; i++) {
                        const b = v[off++];
                        for (let bt=0; bt<8; bt++) {
                            if (b & (0x80 >> bt)) {
                                const tID = wb * 256 + i * 8 + bt;
                                ts.push(TYPE_NAMES[tID] || `TYPE${tID}`);
                            }
                        }
                    }
                }
                d = `${fqdn(name)} ${ts.join(' ')}`;

            } else if (type === 11) { // WKS
                const addr = `${v[off]}.${v[off+1]}.${v[off+2]}.${v[off+3]}`; const prot = v[off+4]; const pts = [];
                for (let i=0; i<len-5; i++) { const b = v[off+5+i]; for (let bt=0; bt<8; bt++) if (b & (0x80 >> bt)) pts.push(i * 8 + bt); }
                d = `${addr} ${prot}${pts.length ? ' ' + pts.join(' ') : ''}`;

            } else if (type === 45) { // IPSECKEY
                const prec = v[off]; const gt = v[off+1]; const al = v[off+2]; let iOff = off+3, gw = "";
                if (gt === 0) gw = "."; else if (gt === 1) { gw = `${v[iOff]}.${v[iOff+1]}.${v[iOff+2]}.${v[iOff+3]}`; iOff += 4; }
                else if (gt === 2) { const p = []; for (let j=0; j<8; j++) p.push(((v[iOff+j*2]<<8)|v[iOff+j*2+1]).toString(16)); gw = compressIPv6(p.join(':')); iOff += 16; }
                else if (gt === 3) { off = iOff; gw = fqdn(parseName()); iOff = off; }
                d = `${prec} ${gt} ${al} ${gw} ${toB64(iOff, start+len)}`;

            } else if (type === 257) { // CAA
                const f = v[off]; const tl = v[off+1]; let t = ""; for (let j=0; j<tl; j++) t += String.fromCharCode(v[off+2+j]);
                let vl = ""; for (let j=tl+2; j<len; j++) vl += String.fromCharCode(v[off+j]); d = `${f} ${t} "${vl}"`;

            } else if (type === 64 || type === 65) { // SVCB, HTTPS
                const prio = (v[off]<<8)|v[off+1]; off += 2; const tgt = parseName(); let ps = "";
                while (off < start + len) {
                    const k = (v[off]<<8)|v[off+1]; const pl = (v[off+2]<<8)|v[off+3]; off += 4;
                    if (k === 1) {
                        let alpn = [], aOff = off; while (aOff < off + pl) { const l = v[aOff++]; alpn.push(String.fromCharCode(...v.slice(aOff, aOff + l))); aOff += l; }
                        ps += ` alpn=${alpn.join(',')}`;
                    } else if (k === 4) {
                        let ips = []; for (let j=0; j<pl; j+=4) ips.push(`${v[off+j]}.${v[off+j+1]}.${v[off+j+2]}.${v[off+j+3]}`);
                        ps += ` ipv4hint=${ips.join(',')}`;
                    } else if (k === 5) {
                        ps += ` ech=${toB64(off, off + pl)}`;
                    } else if (k === 6) {
                        let ips = []; for (let j=0; j<pl; j+=16) { const p = []; for (let k=0; k<8; k++) p.push(((v[off+j+k*2]<<8)|v[off+j+k*2+1]).toString(16)); ips.push(compressIPv6(p.join(':'))); }
                        ps += ` ipv6hint=${ips.join(',')}`;
                    } else { ps += ` key${k}=${toHex(off, off+pl)}`; }
                    off += pl;
                }
                d = `${prio} ${fqdn(tgt)}${ps}`;

            } else {
                const bytes = v.slice(off, off + len);
                d = bytes.every(b => b >= 32 && b <= 126) ? String.fromCharCode(...bytes) : toHex(off, off + len);
            }
        } catch { d = "Error parsing RDATA"; }
        off = start + len;
        return d;
    };

    try {
        const qd = (v[4] << 8) | v[5];
        const an = (v[6] << 8) | v[7];
        const ns = (v[8] << 8) | v[9];
        const ar = (v[10] << 8) | v[11];

        for (let i=0; i<qd && off<v.length; i++) {
            const name = fqdn(parseName());
            const type = (v[off] << 8) | v[off+1];
            res.Question.push({ name, type });
            off += 4;
        }

        const parseSection = (count) => {
            const items = [];
            for (let i=0; i<count && off<v.length; i++) {
                const name = fqdn(parseName());
                const type = (v[off]   << 8) | v[off+1];
                const ttl  = ((v[off+4]<<24|v[off+5]<<16|v[off+6]<<8|v[off+7]) >>> 0);
                const len  = (v[off+8] << 8) | v[off+9];
                off += 10;
                const data = parseRdata(type, len);
                items.push({ name, type, TTL: ttl, data });
            }
            return items;
        };

        res.Answer     = parseSection(an);
        res.Authority  = parseSection(ns);
        res.Additional = parseSection(ar).filter(r => r.type !== 41); // Hide OPT
    } catch { res.Comment = "Parse error"; }
    return res;
}

// Build NXDOMAIN response (RCODE=3) - Domain does not exist
function buildNxdomain(query) {
    const v = new Uint8Array(query);
    if (v.length < 12) {
        const sf = new Uint8Array(12);
        sf[2] = 0x84; sf[3] = 0x82;
        return sf.buffer;
    }
    let qEnd = 12;
    while (qEnd < v.length) {
        const len = v[qEnd];
        if (len === 0) { qEnd++; break; }
        if ((len & 0xC0) === 0xC0) { qEnd += 2; break; }
        qEnd += len + 1;
    }
    qEnd += 4;
    const res = new Uint8Array(qEnd);
    res.set(v.slice(0, qEnd));
    res[2] = 0x80 | (v[2] & 0x7F);
    res[3] = 0x80 | 0x03; // RA=1, RCODE=3 (NXDOMAIN)
    res[4] = 0; res[5] = 1;
    res[6] = 0; res[7] = 0;
    res[8] = 0; res[9] = 0;
    res[10] = 0; res[11] = 0;
    return res.buffer;
}

// NODATA response: RCODE=0 (NOERROR), ANCOUNT=0
function buildNodata(query) {
    const v = new Uint8Array(query);
    if (v.length < 12) {
        const sf = new Uint8Array(12);
        sf[2] = 0x84; sf[3] = 0x80;
        return sf.buffer;
    }
    let qEnd = 12;
    while (qEnd < v.length) {
        const len = v[qEnd];
        if (len === 0) { qEnd++; break; }
        if ((len & 0xC0) === 0xC0) { qEnd += 2; break; }
        qEnd += len + 1;
    }
    qEnd += 4;
    const res = new Uint8Array(qEnd);
    res.set(v.slice(0, qEnd));
    res[2] = 0x80 | (v[2] & 0x7F);
    res[3] = 0x80; // RA=1, RCODE=0 (NOERROR)
    res[4] = 0; res[5] = 1;
    res[6] = 0; res[7] = 0;
    res[8] = 0; res[9] = 0;
    res[10] = 0; res[11] = 0;
    return res.buffer;
}

function buildServfail(query) {
    const v = new Uint8Array(query);
    if (v.length < 12) {
        const sf = new Uint8Array(12);
        sf[2] = 0x84; sf[3] = 0x82;
        return sf.buffer;
    }
    let qEnd = 12;
    while (qEnd < v.length) {
        const len = v[qEnd];
        if (len === 0) { qEnd++; break; }
        if ((len & 0xC0) === 0xC0) { qEnd += 2; break; }
        qEnd += len + 1;
    }
    qEnd += 4;
    const res = new Uint8Array(qEnd);
    res.set(v.slice(0, qEnd));
    res[2] = 0x80 | (v[2] & 0x7F);
    res[3] = 0x80 | 0x02; // RA=1, RCODE=2 (SERVFAIL)
    res[4] = 0; res[5] = 1;
    res[6] = 0; res[7] = 0;
    res[8] = 0; res[9] = 0;
    res[10] = 0; res[11] = 0;
    return res.buffer;
}

// ==================== ECS INJECTION ====================
// Inject EDNS Client Subnet (ECS) into DNS query per RFC 7871
// prefixOverride: override default prefix length (from edns_client_subnet param)
function injectECS(query, clientIP, prefixOverride = null) {
    if (!ECS_INJECTION_ENABLED || !clientIP || clientIP === 'unknown') return query;
    try {
        const v = new Uint8Array(query);
        if (v.length < 12) return query;

        const clean = stripOPT(v);

        const ipv4Mapped = clientIP.match(IPV4_MAPPED_REGEX);
        if (ipv4Mapped) clientIP = ipv4Mapped[1];

        let family, prefixLen, addrBytes;
        if (clientIP.includes(':')) {
            family = 2; prefixLen = prefixOverride ?? ECS_PREFIX_V6;
            const allBytes = ipv6ToBytes(clientIP);
            if (!allBytes) return query;
            const byteLen = Math.ceil(prefixLen / 8);
            addrBytes = allBytes.slice(0, byteLen);
        } else {
            family = 1; prefixLen = prefixOverride ?? ECS_PREFIX_V4;
            const parts = clientIP.split('.');
            if (parts.length !== 4) return query;
            const byteLen = Math.ceil(prefixLen / 8);
            addrBytes = parts.slice(0, byteLen).map(Number);
        }

        if (addrBytes.length > 0 && prefixLen % 8 !== 0) {
            const maskBits = prefixLen % 8;
            const mask = (0xFF << (8 - maskBits)) & 0xFF;
            addrBytes[addrBytes.length - 1] &= mask;
        }

        const ecsLen = 4 + addrBytes.length;
        const ecs = new Uint8Array(4 + ecsLen);
        ecs[0] = 0; ecs[1] = 8;
        ecs[2] = (ecsLen >> 8) & 0xFF; ecs[3] = ecsLen & 0xFF;
        ecs[4] = (family >> 8) & 0xFF; ecs[5] = family & 0xFF;
        ecs[6] = prefixLen; ecs[7] = 0;
        for (let i = 0; i < addrBytes.length; i++) ecs[8 + i] = addrBytes[i];

        const opt = new Uint8Array(11 + ecs.length);
        opt[0] = 0;
        opt[1] = 0; opt[2] = 41;
        opt[3] = 16; opt[4] = 0;
        opt[5] = 0; opt[6] = 0; opt[7] = 0; opt[8] = 0;
        opt[9] = (ecs.length >> 8) & 0xFF; opt[10] = ecs.length & 0xFF;
        opt.set(ecs, 11);

        const currentArCount = (clean[10] << 8) | clean[11];
        const newArCount = currentArCount + 1;

        const result = new Uint8Array(clean.length + opt.length);
        result.set(clean);
        result.set(opt, clean.length);
        result[10] = (newArCount >> 8) & 0xFF;
        result[11] = newArCount & 0xFF;
        return result.buffer;
    } catch { return query; }
}

// Strip existing OPT (EDNS) records from DNS query
function stripOPT(view) {
    let off = 12;
    const qd = (view[4] << 8) | view[5];
    for (let i = 0; i < qd && off < view.length; i++) {
        while (off < view.length) {
            const l = view[off];
            if (l === 0) { off++; break; }
            if ((l & 0xC0) === 0xC0) { off += 2; break; }
            off += l + 1;
        }
        off += 4;
    }
    const an = (view[6] << 8) | view[7];
    const ns = (view[8] << 8) | view[9];
    for (let i = 0; i < an + ns && off < view.length; i++) {
        while (off < view.length) {
            const l = view[off];
            if (l === 0) { off++; break; }
            if ((l & 0xC0) === 0xC0) { off += 2; break; }
            off += l + 1;
        }
        if (off + 10 > view.length) break;
        off += 10 + ((view[off + 8] << 8) | view[off + 9]);
    }
    const ar = (view[10] << 8) | view[11];
    let arOff = off;
    const keptRecords = [];
    for (let i = 0; i < ar && arOff < view.length; i++) {
        const recStart = arOff;
        while (arOff < view.length) {
            const l = view[arOff];
            if (l === 0) { arOff++; break; }
            if ((l & 0xC0) === 0xC0) { arOff += 2; break; }
            arOff += l + 1;
        }
        if (arOff + 10 > view.length) break;
        const type  = (view[arOff] << 8) | view[arOff + 1];
        const rdlen = (view[arOff + 8] << 8) | view[arOff + 9];
        if (arOff + 10 + rdlen > view.length) break;
        arOff += 10 + rdlen;
        if (type !== 41) keptRecords.push(view.subarray(recStart, arOff));
    }
    let totalLen = off;
    for (const rec of keptRecords) totalLen += rec.length;
    const r = new Uint8Array(totalLen);
    r.set(view.subarray(0, off));
    let writeOff = off;
    for (const rec of keptRecords) { r.set(rec, writeOff); writeOff += rec.length; }
    r[10] = (keptRecords.length >> 8) & 0xFF;
    r[11] = keptRecords.length & 0xFF;
    return r;
}

// Convert IPv6 address string to 16-byte array
function ipv6ToBytes(ip) {
    try {
        if (!ip || typeof ip !== 'string') return null;
        if (!IPV6_VALID_REGEX.test(ip)) return null;

        const halves = ip.split('::');
        if (halves.length > 2) return null;

        const left  = halves[0] ? halves[0].split(':').filter(x => x) : [];
        const right = halves.length > 1 && halves[1] ? halves[1].split(':').filter(x => x) : [];
        const totalGroups = left.length + right.length;
        if (totalGroups > 8) return null;

        for (const g of [...left, ...right]) {
            if (g.length > 4 || !IPV6_GROUP_REGEX.test(g)) return null;
        }

        const missing = 8 - totalGroups;
        const full = [...left, ...Array(missing).fill('0'), ...right];
        const bytes = [];
        for (const s of full) {
            const v = parseInt(s || '0', 16);
            if (isNaN(v)) return null;
            bytes.push((v >> 8) & 0xFF, v & 0xFF);
        }
        return bytes;
    } catch { return null; }
}

// ==================== DNS REDIRECT ====================
function encodeDomainName(domain) {
    if (!domain || domain === '.') return new Uint8Array([0]);
    const parts = domain.replace(/\.$/, '').split('.');
    let totalLen = 0;
    for (const p of parts) totalLen += p.length + 1;
    const buf = new Uint8Array(totalLen + 1);
    let off = 0;
    for (const p of parts) {
        buf[off++] = p.length;
        for (let i = 0; i < p.length; i++) buf[off++] = p.charCodeAt(i);
    }
    buf[off++] = 0;
    return buf;
}

function decodeName(v, startOff) {
    let labels = [];
    let curr = startOff;
    let jumped = false;
    let nextOff = -1;
    let depth = 0;
    while (depth < 20 && curr < v.length) {
        const b = v[curr];
        if (b === 0) {
            if (!jumped) nextOff = curr + 1;
            curr++;
            break;
        }
        if ((b & 0xC0) === 0xC0) {
            if (curr + 1 >= v.length) break;
            const ptr = ((b & 0x3F) << 8) | v[curr + 1];
            if (!jumped) nextOff = curr + 2;
            jumped = true;
            curr = ptr;
            depth++;
        } else {
            const l = v[curr++];
            if (curr + l > v.length) break;
            let label = "";
            for (let i = 0; i < l; i++) label += String.fromCharCode(v[curr++]);
            labels.push(label);
        }
    }
    return { name: labels.length === 0 ? "." : labels.join('.'), nextOff: jumped ? nextOff : curr };
}

function rewriteQname(query, targetDomain) {
    const v = new Uint8Array(query);
    if (v.length < 12) return query;
    let qnameEnd = 12;
    while (qnameEnd < v.length) {
        const len = v[qnameEnd];
        if (len === 0) { qnameEnd++; break; }
        if ((len & 0xC0) === 0xC0) { qnameEnd += 2; break; }
        qnameEnd += len + 1;
    }
    const targetWire = encodeDomainName(targetDomain);
    const afterQname = v.subarray(qnameEnd);
    const result = new Uint8Array(12 + targetWire.length + afterQname.length);
    result.set(v.subarray(0, 12));
    result.set(targetWire, 12);
    result.set(afterQname, 12 + targetWire.length);
    return result.buffer;
}

function buildRedirectResponse(originalQuery, upstreamResponse, originalDomain, targetDomain) {
    const uv = new Uint8Array(upstreamResponse);
    const qv = new Uint8Array(originalQuery);
    if (uv.length < 12 || qv.length < 12) return upstreamResponse;

    let uOff = 12;
    const uQd = (uv[4] << 8) | uv[5];
    for (let i = 0; i < uQd; i++) {
        uOff = decodeName(uv, uOff).nextOff + 4;
    }

    const anCount = (uv[6] << 8) | uv[7];
    const ansRecords = [];
    for (let i = 0; i < anCount && uOff < uv.length; i++) {
        const dn = decodeName(uv, uOff);
        uOff = dn.nextOff;
        if (uOff + 10 > uv.length) break;
        const type  = (uv[uOff]   << 8) | uv[uOff + 1];
        const cls   = (uv[uOff+2] << 8) | uv[uOff + 3];
        const ttl   = ((uv[uOff+4]<<24)|(uv[uOff+5]<<16)|(uv[uOff+6]<<8)|uv[uOff+7]) >>> 0;
        const rdlen = (uv[uOff+8] << 8) | uv[uOff + 9];
        uOff += 10;
        if (uOff + rdlen > uv.length) break;

        let rdata = uv.slice(uOff, uOff + rdlen);
        if (type === 5 || type === 2 || type === 12) { // CNAME, NS, PTR
            rdata = encodeDomainName(decodeName(uv, uOff).name);
        } else if (type === 15) { // MX
            const pref = uv.slice(uOff, uOff + 2);
            const name = encodeDomainName(decodeName(uv, uOff + 2).name);
            const combined = new Uint8Array(2 + name.length);
            combined.set(pref); combined.set(name, 2);
            rdata = combined;
        } else if (type === 33) { // SRV
            const fixed = uv.slice(uOff, uOff + 6);
            const name = encodeDomainName(decodeName(uv, uOff + 6).name);
            const combined = new Uint8Array(6 + name.length);
            combined.set(fixed); combined.set(name, 6);
            rdata = combined;
        }
        ansRecords.push({ type, cls, ttl, rdata });
        uOff += rdlen;
    }

    let oQEnd = 12;
    oQEnd = decodeName(qv, 12).nextOff + 4;

    const targetWire = encodeDomainName(targetDomain);
    const cnameSize = 2 + 10 + targetWire.length;
    let ansSize = 0;
    for (const rec of ansRecords) ansSize += targetWire.length + 10 + rec.rdata.length;

    const res = new Uint8Array(oQEnd + cnameSize + ansSize);
    res.set(qv.subarray(0, oQEnd));
    res[2] = 0x80 | (qv[2] & 0x7F);
    res[3] = uv[3];
    res[4] = 0; res[5] = 1;
    const newAnCount = 1 + ansRecords.length;
    res[6] = (newAnCount >> 8) & 0xFF;
    res[7] = newAnCount & 0xFF;
    res[8] = 0; res[9] = 0;
    res[10] = 0; res[11] = 0;

    let off = oQEnd;
    res[off++] = 0xC0; res[off++] = 0x0C; // Pointer to original query name
    res[off++] = 0x00; res[off++] = 0x05; // TYPE CNAME
    res[off++] = 0x00; res[off++] = 0x01; // CLASS IN
    res[off++] = 0x00; res[off++] = 0x00;
    res[off++] = 0x01; res[off++] = 0x2C; // TTL 300
    res[off++] = (targetWire.length >> 8) & 0xFF;
    res[off++] = targetWire.length & 0xFF;
    res.set(targetWire, off); off += targetWire.length;

    for (const rec of ansRecords) {
        res.set(targetWire, off); off += targetWire.length;
        res[off++] = (rec.type >> 8) & 0xFF; res[off++] = rec.type & 0xFF;
        res[off++] = (rec.cls >> 8) & 0xFF; res[off++] = rec.cls & 0xFF;
        res[off++] = (rec.ttl >> 24) & 0xFF; res[off++] = (rec.ttl >> 16) & 0xFF;
        res[off++] = (rec.ttl >> 8) & 0xFF; res[off++] = rec.ttl & 0xFF;
        res[off++] = (rec.rdata.length >> 8) & 0xFF; res[off++] = rec.rdata.length & 0xFF;
        res.set(rec.rdata, off); off += rec.rdata.length;
    }
    return res.buffer;
}

// ==================== DNS FORWARDING ====================
async function forwardQuery(query, upstream) {
    const res = await fetch(upstream, {
        method: 'POST',
        headers: { 'Content-Type': 'application/dns-message', 'Accept': 'application/dns-message' },
        body: query,
        signal: AbortSignal.timeout(UPSTREAM_TIMEOUT)
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.arrayBuffer();
}

// Resolve DNS query with fallback and geo-bypass logic
// prefixOverride: custom ECS prefix length from edns_client_subnet param
async function resolveQuery(query, clientIP, prefixOverride = null) {
    const processed = injectECS(query, clientIP, prefixOverride);
    let result;
    try {
        result = await forwardQuery(processed, UPSTREAM_PRIMARY);
    } catch {
        try {
            result = await forwardQuery(processed, UPSTREAM_FALLBACK);
        } catch {
            return buildServfail(query);
        }
    }

    if (result && hasLoopbackInAnswer(result)) {
        try {
            const respMullvad = await forwardQuery(processed, UPSTREAM_GEO_BYPASS);
            if (!hasLoopbackInAnswer(respMullvad)) return respMullvad;
            return buildNxdomain(query);
        } catch {
            return buildServfail(query);
        }
    }

    return result;
}

// ==================== HELPERS ====================
async function ensureBlocklistsLoaded(url, context) {
    // Always kick off refresh in the background (waitUntil) without blocking DNS resolution.
    // refreshBlocklists() has its own TTL guard, so it's a no-op when the list is fresh.
    // Trade-off: on cold start or during a refresh window, a small number of requests may
    // resolve without adblock — acceptable given the low probability of hitting a blocked
    // domain in that narrow window.
    if (context) {
        context.waitUntil(refreshBlocklists(url));
    } else {
        await refreshBlocklists(url);
    }
}

// ==================== HANDLERS ====================
async function handleDNSQuery(request, context) {
    const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
    const cors = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type, Accept' };
    const url = new URL(request.url);
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });

    let query;
    const domainParam = url.searchParams.get('domain') || url.searchParams.get('name');

    // Parse edns_client_subnet: e.g. "103.186.65.82" or "103.186.65.0/24" or "2001:db8::/32"
    let ecsIP = clientIP, ecsPrefix = null;
    if (domainParam) {
        const ecsParam = url.searchParams.get('edns_client_subnet');
        if (ecsParam) {
            const slash = ecsParam.indexOf('/');
            ecsIP    = slash !== -1 ? ecsParam.slice(0, slash) : ecsParam;
            ecsPrefix = slash !== -1 ? parseInt(ecsParam.slice(slash + 1)) : null;
        }
    }

    if (domainParam) {
        const typeParam = url.searchParams.get('type') || 'A';
        let qtype = 1;

        // Try to parse as integer first (e.g. ?type=28)
        const parsedInt = parseInt(typeParam);
        if (!isNaN(parsedInt)) {
            qtype = parsedInt;
        } else {
            const typeStr = typeParam.toUpperCase();
            const typeMap = {
                'A': 1, 'NS': 2, 'MD': 3, 'MF': 4, 'CNAME': 5, 'SOA': 6, 'MB': 7, 'MG': 8, 'MR': 9, 'NULL': 10,
                'WKS': 11, 'PTR': 12, 'HINFO': 13, 'MINFO': 14, 'MX': 15, 'TXT': 16, 'RP': 17, 'AFSDB': 18, 'X25': 19, 'ISDN': 20,
                'RT': 21, 'NSAP': 22, 'NSAP-PTR': 23, 'SIG': 24, 'KEY': 25, 'PX': 26, 'GPOS': 27, 'AAAA': 28, 'LOC': 29, 'NXT': 30,
                'EID': 31, 'NIMLOC': 32, 'SRV': 33, 'ATMA': 34, 'NAPTR': 35, 'KX': 36, 'CERT': 37, 'A6': 38, 'DNAME': 39, 'SINK': 40,
                'OPT': 41, 'APL': 42, 'DS': 43, 'SSHFP': 44, 'IPSECKEY': 45, 'RRSIG': 46, 'NSEC': 47, 'DNSKEY': 48, 'DHCID': 49, 'NSEC3': 50,
                'NSEC3PARAM': 51, 'TLSA': 52, 'SMIMEA': 53, 'HIP': 55, 'NINFO': 56, 'RKEY': 57, 'TALINK': 58, 'CDS': 59, 'CDNSKEY': 60,
                'OPENPGPKEY': 61, 'CSYNC': 62, 'ZONEMD': 63, 'SVCB': 64, 'HTTPS': 65, 'DSYNC': 66, 'HHIT': 67, 'BRID': 68, 'SPF': 99, 'UINFO': 100,
                'UID': 101, 'GID': 102, 'UNSPEC': 103, 'NID': 104, 'L32': 105, 'L64': 106, 'LP': 107, 'EUI48': 108, 'EUI64': 109, 'NXNAME': 128,
                'TKEY': 249, 'TSIG': 250, 'IXFR': 251, 'AXFR': 252, 'MAILB': 253, 'MAILA': 254, 'ANY': 255, 'ALL': 255, 'URI': 256, 'CAA': 257, 'AVC': 258,
                'DOA': 259, 'AMTRELAY': 260, 'RESINFO': 261, 'WALLET': 262, 'CLA': 263, 'IPN': 264, 'TA': 32768, 'DLV': 32769
            };
            qtype = typeMap[typeStr] || 1;
        }
        let finalDomain = domainParam.toLowerCase();
        // If query type is PTR (12) or NAPTR (35) and name is an IP address, auto-convert to reverse domain
        const checkIP = finalDomain.endsWith('.') ? finalDomain.slice(0, -1) : finalDomain;
        if ((qtype === 12 || qtype === 35) && isValidIP(checkIP)) {
            finalDomain = ipToReverseDomain(checkIP);
        }
        const qname = encodeDomainName(finalDomain);
        const buf = new Uint8Array(12 + qname.length + 4);
        const id = Math.floor(Math.random() * 65536);
        buf.set([id >> 8, id & 0xFF, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        buf.set(qname, 12);
        const qOff = 12 + qname.length;
        buf[qOff] = qtype >> 8; buf[qOff+1] = qtype & 0xFF; // QTYPE (16-bit)
        buf[qOff+2] = 0; buf[qOff+3] = 1; // QCLASS (IN)
        query = buf.buffer;
    } else if (request.method === 'POST') {
        query = await request.arrayBuffer();
    } else if (request.method === 'GET') {
        const dns = url.searchParams.get('dns');
        if (!dns) return new Response('Missing dns parameter', { status: 400, headers: cors });
        const b64 = dns.replace(/-/g, '+').replace(/_/g, '/');
        const padded = b64 + '=='.slice(0, (4 - b64.length % 4) % 4);
        query = Uint8Array.from(atob(padded), c => c.charCodeAt(0)).buffer;
    } else {
        return new Response('Method not allowed', { status: 405, headers: cors });
    }

    // Block unwanted query types early to save upstream requests
    if (BLOCKED_QTYPES.size > 0) {
        const qtype = extractQtype(query);
        if (qtype !== null && BLOCKED_QTYPES.has(qtype)) {
            const data = buildNodata(query);
            if (domainParam) return new Response(JSON.stringify(dnsResponseToJson(data)), { headers: { ...cors, 'Content-Type': 'application/json', 'X-Blocked-Type': String(qtype) } });
            return new Response(data, { headers: { ...cors, 'Content-Type': 'application/dns-message', 'X-Blocked-Type': String(qtype) } });
        }
    }

    // Load data if any domain-based filter is enabled
    if (AD_BLOCK_ENABLED || BLOCK_PRIVATE_TLD || DNS_REDIRECT_ENABLED || MULLVAD_UPSTREAM_ENABLED) {
        await ensureBlocklistsLoaded(request.url, context);

        const domains = extractAllDomains(query);
        for (const domain of domains) {
            if (!domain) continue;

            // Mullvad Dedicated Upstream
            if (MULLVAD_UPSTREAM_ENABLED && isMullvadDomain(domain)) {
                try {
                    const processed = injectECS(query, ecsIP, ecsPrefix);
                    const data = await forwardQuery(processed, UPSTREAM_GEO_BYPASS);
                    if (domainParam) return new Response(JSON.stringify(dnsResponseToJson(data)), { headers: { ...cors, 'Content-Type': 'application/json', 'X-Upstream': 'Mullvad' } });
                    return new Response(data, { headers: { ...cors, 'Content-Type': 'application/dns-message', 'X-Upstream': 'Mullvad' } });
                } catch {
                    const data = buildServfail(query);
                    if (domainParam) return new Response(JSON.stringify(dnsResponseToJson(data)), { headers: { ...cors, 'Content-Type': 'application/json', 'X-Upstream': 'Mullvad-Failed' } });
                    return new Response(data, { headers: { ...cors, 'Content-Type': 'application/dns-message', 'X-Upstream': 'Mullvad-Failed' } });
                }
            }

            // Private TLD check (NXDOMAIN)
            if (BLOCK_PRIVATE_TLD && isDomainPrivate(domain)) {
                const data = buildNxdomain(query);
                if (domainParam) return new Response(JSON.stringify(dnsResponseToJson(data)), { headers: { ...cors, 'Content-Type': 'application/json', 'X-Blocked-Private': domain } });
                return new Response(data, { headers: { ...cors, 'Content-Type': 'application/dns-message', 'X-Blocked-Private': domain } });
            }

            // Ad block check (NXDOMAIN)
            if (AD_BLOCK_ENABLED && isDomainBlocked(domain)) {
                const data = buildNxdomain(query);
                if (domainParam) return new Response(JSON.stringify(dnsResponseToJson(data)), { headers: { ...cors, 'Content-Type': 'application/json', 'X-Blocked': domain } });
                return new Response(data, { headers: { ...cors, 'Content-Type': 'application/dns-message', 'X-Blocked': domain } });
            }

            // DNS redirect
            if (DNS_REDIRECT_ENABLED && redirectRules.has(domain)) {
                const targetDomain = redirectRules.get(domain);
                try {
                    const rewritten = rewriteQname(query, targetDomain);
                    let data = await resolveQuery(rewritten, ecsIP, ecsPrefix);
                    data = buildRedirectResponse(query, data, domain, targetDomain);
                    if (domainParam) return new Response(JSON.stringify(dnsResponseToJson(data)), { headers: { ...cors, 'Content-Type': 'application/json', 'X-Redirected': `${domain} -> ${targetDomain}` } });
                    return new Response(data, { headers: { ...cors, 'Content-Type': 'application/dns-message', 'X-Redirected': `${domain} -> ${targetDomain}` } });
                } catch { }
            }
        }
    }

    // Forward to upstream
    try {
        const data = await resolveQuery(query, ecsIP, ecsPrefix);
        if (domainParam) return new Response(JSON.stringify(dnsResponseToJson(data)), { headers: { ...cors, 'Content-Type': 'application/json' } });
        return new Response(data, { headers: { ...cors, 'Content-Type': 'application/dns-message' } });
    } catch (e) {
        return new Response(JSON.stringify({ Status: 2, Comment: `Upstream error: ${e.message}` }), { status: 502, headers: { ...cors, 'Content-Type': 'application/json' } });
    }
}

// ==================== ROUTING ====================
async function handleRequest(request, context) {
    const path = new URL(request.url).pathname;

    if (path === '/dns-query') return handleDNSQuery(request, context);

    if (path === '/apple') {
        const host = new URL(request.url).hostname;
        const dohUrl = `https://${host}/dns-query`;
        const uuid1 = crypto.randomUUID();
        const uuid2 = crypto.randomUUID();
        const uuid3 = crypto.randomUUID();
        const profile = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>DNSSettings</key>
            <dict>
                <key>DNSProtocol</key>
                <string>HTTPS</string>
                <key>ServerURL</key>
                <string>${dohUrl}</string>
            </dict>
            <key>PayloadDescription</key>
            <string>Private DNS Resolution by ${host}</string>
            <key>PayloadDisplayName</key>
            <string>${host} DoH</string>
            <key>PayloadIdentifier</key>
            <string>com.cloudflare.${uuid1}.dnsSettings.managed</string>
            <key>PayloadType</key>
            <string>com.apple.dnsSettings.managed</string>
            <key>PayloadUUID</key>
            <string>${uuid3}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>ProhibitDisablement</key>
            <false/>
        </dict>
    </array>
    <key>PayloadDescription</key>
    <string>Private DNS Resolution by ${host}
    - Privacy &amp; Zero Logs
    - Global Anycast Network
    - Smart Ad Blocking</string>
    <key>PayloadDisplayName</key>
    <string>${host} DoH</string>
    <key>PayloadIdentifier</key>
    <string>com.cloudflare.${uuid2}</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>${uuid2}</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>`;
        return new Response(profile, {
            headers: {
                'Content-Type': 'application/x-apple-aspen-config',
                'Content-Disposition': `attachment; filename="${host}.mobileconfig"`
            }
        });
    }

    return new Response('Not Found', { status: 404 });
}

export async function onRequest(context) {
    return handleRequest(context.request, context);
}
