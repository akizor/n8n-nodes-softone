"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SoftOne = void 0;
const n8n_workflow_1 = require("n8n-workflow");
// ---------- SQL preset catalogue ----------
const SQL_PRESETS = [
    { name: 'Custom…', value: '__custom__', description: 'Enter any SqlName manually' },
    { name: 'Countries (Tari)', value: 'Tari', description: 'List countries' },
    { name: 'Zones / Counties (Judete)', value: 'Judete', description: 'List zones / counties' },
    { name: 'Currencies (Monede)', value: 'Monede', description: 'List currencies' },
    { name: 'Customers / Suppliers by VAT (trdr1)', value: 'trdr1', description: 'Lookup PJ customer / supplier. Set type in param1 (12=supplier, 13=customer) and VAT in param2.' },
    { name: 'Private Customers by Phone (trdr2)', value: 'trdr2', description: 'Lookup PF customer. Phone in param1.' },
    { name: 'Customer Verticals (custcateg)', value: 'custcateg', description: 'List customer verticals' },
    { name: 'Employees (angajati)', value: 'angajati', description: 'List active employees' },
    { name: 'All Employees (angajati1)', value: 'angajati1', description: 'List all employees incl. inactive' },
    { name: 'Payments (payment1)', value: 'payment1', description: 'List payment methods' },
    { name: 'Past Due Invoices (scadentec)', value: 'scadentec', description: 'Past due invoices across customers' },
    { name: 'Past Due Invoices by Customer (scadentec1)', value: 'scadentec1', description: 'Past due invoices for a single customer' },
    { name: 'Invoices & Receipts (findfindoc)', value: 'findfindoc', description: 'Search invoices / receipts' },
    { name: 'Products Finder (finditems)', value: 'finditems', description: 'Find products. param1: 51=stock, 52=service. param2: code list.' },
    { name: 'Cost Prices (pretcost)', value: 'pretcost', description: 'Cost price per product' },
    { name: 'NIR by ID (getnirbyid)', value: 'getnirbyid', description: 'Fetch a NIR / purchase document by ID' },
    { name: 'Gov Categories (cpvcodes)', value: 'cpvcodes', description: 'CPV / government categories' },
    { name: 'Agent Sales (vanzariagent)', value: 'vanzariagent', description: 'Agent sales report' },
    { name: 'Agent Sales v2 (vanzariagentv2)', value: 'vanzariagentv2', description: 'Agent sales report (v2)' },
    { name: 'Projects (prjc)', value: 'prjc', description: 'List SoftOne projects' },
    { name: 'Transporters (transportatori)', value: 'transportatori', description: 'List transporters' },
    { name: 'Customs / SAFT Tax (safttaxsql)', value: 'safttaxsql', description: 'Customs / SAFT tax data' },
    { name: 'UIT Code (getuitcode1)', value: 'getuitcode1', description: 'Fetch UIT code for a document' },
];
const OBJECT_PRESETS = [
    { name: 'Custom…', value: '__custom__', description: 'Enter any SoftOne OBJECT manually' },
    { name: 'Customer (CUSTOMER)', value: 'CUSTOMER', description: 'Customer master data' },
    { name: 'Supplier (SUPPLIER)', value: 'SUPPLIER', description: 'Supplier master data' },
    { name: 'Item / Product (ITEM)', value: 'ITEM', description: 'Product / service master data' },
    { name: 'Product Category (MTRCATEGORY)', value: 'MTRCATEGORY', description: 'Product category master data' },
    { name: 'Manufacturer (MTRMANFCTR)', value: 'MTRMANFCTR', description: 'Manufacturer master data' },
    { name: 'Person (PRSN)', value: 'PRSN', description: 'User / person record' },
    { name: 'Sales Document (FINDOC)', value: 'FINDOC', description: 'Invoice / receipt / sale doc' },
    { name: 'Purchase Document (PURDOC)', value: 'PURDOC', description: 'Purchase doc' },
    { name: 'Material Document (MTRDOC)', value: 'MTRDOC', description: 'NIR / material doc' },
];
// ---------- Error codes ----------
const S1_ERROR_CODES = {
    '-101': 'Session expired (web account time expiration). Re-authenticate.',
    '-100': 'Session expired (deep-linking smart command).',
    '-12': 'Invalid web service call.',
    '-11': 'License must include a "Web Service Connector" module.',
    '-10': 'Login fails — username contains illegal characters.',
    '-9': 'Invalid request. Ensure your request is valid.',
    '-8': 'User account is not active.',
    '-7': 'Session expired (FinalDate on web account).',
    '-6': 'Invalid AppId — the AppId in the request does not match the one in the clientID.',
    '-5': 'Web-service licences exceeded.',
    '-4': 'Number of registered devices exceeded.',
    '-3': 'Access denied — selected module not activated.',
    '-2': 'Authenticate failed — invalid credentials.',
    '-1': 'Invalid request — please login first.',
    '11': 'Internal server error.',
    '12': 'Deprecated service.',
    '13': 'Invalid request — reqID expired.',
    '14': 'Invalid WS request — check SerialNumber.',
    '101': 'Insufficient access rights. Check module or web-account user licences.',
    '102': 'reqID not found on server.',
    '213': 'Invalid request — reqID expired.',
    '1001': 'Ensure username, password, user-is-active, and administrator right.',
    '2001': 'Data does not exist.',
};
function decorateS1Error(response) {
    const code = response.errorcode ?? response.code;
    const raw = typeof response.error === 'string' ? response.error : 'unknown';
    if (code !== undefined) {
        const hint = S1_ERROR_CODES[String(code)];
        return hint ? `${raw} [${code}: ${hint}]` : `${raw} [code ${code}]`;
    }
    return raw;
}
// ---------- Security helpers ----------
const SENSITIVE_KEYS = new Set([
    'password', 'Password', 'PASSWORD',
    'username', 'Username', 'USERNAME',
    'clientID', 'clientId', 'CLIENTID',
    'appid', 'appId', 'APPID',
    'pin', 'PIN',
    'sn', 'SN',
]);
const FORBIDDEN_JSON_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
function redactSecrets(value) {
    if (Array.isArray(value))
        return value.map(redactSecrets);
    if (value !== null && typeof value === 'object') {
        const out = {};
        for (const [k, v] of Object.entries(value)) {
            out[k] = SENSITIVE_KEYS.has(k) ? '***REDACTED***' : redactSecrets(v);
        }
        return out;
    }
    return value;
}
function stripPrototypeKeys(value) {
    if (Array.isArray(value))
        return value.map(stripPrototypeKeys);
    if (value !== null && typeof value === 'object') {
        const out = {};
        for (const [k, v] of Object.entries(value)) {
            if (FORBIDDEN_JSON_KEYS.has(k))
                continue;
            out[k] = stripPrototypeKeys(v);
        }
        return out;
    }
    return value;
}
function sanitizeFileName(raw) {
    const base = (raw ?? '').toString();
    const noSep = base.replace(/[\\/\x00]/g, '_');
    const noTraversal = noSep
        .split(/[./]/)
        .filter((seg) => seg !== '..' && seg !== '.')
        .join('.');
    const trimmed = noTraversal.replace(/^\.+/, '').trim();
    return trimmed.length > 0 ? trimmed : 'softone-document';
}
function isSuccessFalse(response) {
    if (response === null || typeof response !== 'object')
        return false;
    const s = response.success;
    return s === false || s === 'false' || s === 0 || s === '0';
}
function ipv4ToInt(ip) {
    return ip.split('.').reduce((acc, oct) => (acc << 8) + Number(oct), 0) >>> 0;
}
const PRIVATE_IPV4_RANGES = [
    [ipv4ToInt('10.0.0.0'), ipv4ToInt('10.255.255.255')],
    [ipv4ToInt('127.0.0.0'), ipv4ToInt('127.255.255.255')],
    [ipv4ToInt('169.254.0.0'), ipv4ToInt('169.254.255.255')],
    [ipv4ToInt('172.16.0.0'), ipv4ToInt('172.31.255.255')],
    [ipv4ToInt('192.168.0.0'), ipv4ToInt('192.168.255.255')],
    [ipv4ToInt('0.0.0.0'), ipv4ToInt('0.255.255.255')],
];
function isForbiddenHost(hostname) {
    const h = hostname.toLowerCase();
    if (h === 'localhost' || h === '0.0.0.0' || h === '[::]' || h === '::' || h === '::1')
        return true;
    if (h.endsWith('.local') || h.endsWith('.internal'))
        return true;
    if (/^\d+\.\d+\.\d+\.\d+$/.test(h)) {
        const n = ipv4ToInt(h);
        return PRIVATE_IPV4_RANGES.some(([lo, hi]) => n >= lo && n <= hi);
    }
    if (h.startsWith('[') && h.endsWith(']')) {
        const inner = h.slice(1, -1);
        if (inner.startsWith('fe80:') || inner.startsWith('fc') || inner.startsWith('fd'))
            return true;
        if (inner === '::1')
            return true;
    }
    return false;
}
function validateHost(host, allowUnsafe) {
    let url;
    try {
        url = new URL(host);
    }
    catch {
        throw new Error(`Invalid SoftOne host URL: ${host}`);
    }
    if (allowUnsafe)
        return url;
    if (url.protocol !== 'https:') {
        throw new Error(`SoftOne host must use https:// (got ${url.protocol}). Enable "Allow Unsafe Host" in the credential only for trusted development endpoints.`);
    }
    if (isForbiddenHost(url.hostname)) {
        throw new Error(`SoftOne host ${url.hostname} is on a private/loopback/link-local/metadata range. Enable "Allow Unsafe Host" in the credential if this is intended.`);
    }
    return url;
}
function sanitizeEndpointPath(raw) {
    const trimmed = (raw ?? '').trim();
    if (!trimmed)
        throw new Error('Endpoint Path is required.');
    if (!trimmed.startsWith('/'))
        throw new Error('Endpoint Path must start with "/".');
    if (trimmed.includes('?') || trimmed.includes('#'))
        throw new Error('Endpoint Path must not contain query string or fragment.');
    if (!/^[A-Za-z0-9/_.\-]+$/.test(trimmed))
        throw new Error('Endpoint Path contains unsupported characters. Allowed: letters, digits, "/", "_", ".", "-".');
    if (trimmed.split('/').some((seg) => seg === '..'))
        throw new Error('Endpoint Path must not contain ".." segments.');
    return trimmed;
}
function encodeFilterValue(v) {
    return v.replace(/&/g, '%26').replace(/=/g, '%3D').replace(/\|/g, '%7C');
}
function compileFilters(rows) {
    const parts = [];
    for (const r of rows) {
        const field = (r.field ?? '').trim();
        if (!field)
            continue;
        const op = r.operator ?? 'equals';
        const v = r.value ?? '';
        let clause;
        switch (op) {
            case 'equals':
                clause = `${field}=${encodeFilterValue(v)}`;
                break;
            case 'contains':
                clause = `${field}=%${encodeFilterValue(v)}%`;
                break;
            case 'startsWith':
                clause = `${field}=${encodeFilterValue(v)}%`;
                break;
            case 'endsWith':
                clause = `${field}=%${encodeFilterValue(v)}`;
                break;
            case 'range':
                clause = `${field}=${encodeFilterValue(r.valueFrom ?? '')}...${encodeFilterValue(r.valueTo ?? '')}`;
                break;
            case 'inList': {
                const values = v.split('|').map((s) => s.trim()).filter(Boolean);
                if (values.length === 0)
                    continue;
                clause = `${field}=${values.map(encodeFilterValue).join('|')}`;
                break;
            }
            case 'isTrue':
                clause = `${field}=1`;
                break;
            case 'isFalse':
                clause = `${field}=0`;
                break;
            default:
                throw new Error(`Unknown filter operator: ${op}`);
        }
        parts.push(clause);
    }
    return parts.join('&');
}
function buildFormDataWithClientId(raw, clientID) {
    const stripped = (raw ?? '')
        .split('&')
        .filter((p) => p.length > 0 && !/^clientid=/i.test(p))
        .join('&');
    const injected = `clientID=${encodeURIComponent(clientID)}`;
    return stripped.length > 0 ? `${injected}&${stripped}` : injected;
}
// ---------- HTTP ----------
async function callJson(ctx, creds, body, itemIndex) {
    const url = validateHost(creds.host, Boolean(creds.allowUnsafeHost));
    const response = (await ctx.helpers.httpRequest.call(ctx, {
        method: 'POST',
        url: url.toString().replace(/\/$/, ''),
        body,
        json: true,
        timeout: 90000,
        disableFollowRedirect: true,
        skipSslCertificateValidation: false,
    }));
    if (isSuccessFalse(response)) {
        const safe = redactSecrets(response);
        throw new n8n_workflow_1.NodeApiError(ctx.getNode(), safe, {
            message: `SoftOne API error: ${decorateS1Error(response)}`,
            itemIndex,
        });
    }
    return response ?? {};
}
async function callText(ctx, creds, body) {
    const url = validateHost(creds.host, Boolean(creds.allowUnsafeHost));
    const response = await ctx.helpers.httpRequest.call(ctx, {
        method: 'POST',
        url: url.toString().replace(/\/$/, ''),
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        encoding: 'text',
        timeout: 90000,
        disableFollowRedirect: true,
        skipSslCertificateValidation: false,
    });
    return typeof response === 'string' ? response : String(response);
}
async function callRawPost(ctx, url, postData, asBinary) {
    const response = await ctx.helpers.httpRequest.call(ctx, {
        method: 'POST',
        url,
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'cache-control': 'no-cache',
        },
        body: postData,
        encoding: asBinary ? 'arraybuffer' : 'text',
        returnFullResponse: false,
        timeout: 30000,
        disableFollowRedirect: true,
        skipSslCertificateValidation: false,
    });
    if (asBinary) {
        return Buffer.isBuffer(response) ? response : Buffer.from(response);
    }
    return typeof response === 'string' ? response : String(response);
}
// ---------- Auth flow ----------
async function loginOnce(ctx, creds, itemIndex) {
    const body = {
        service: 'login',
        username: creds.username,
        password: creds.password,
        appId: creds.appId,
    };
    if (creds.loginDate)
        body.LOGINDATE = creds.loginDate;
    return (await callJson(ctx, creds, body, itemIndex));
}
function pickCompany(login, companyId, ctx, itemIndex) {
    const companies = login.objs ?? [];
    if (companies.length === 0) {
        throw new n8n_workflow_1.NodeOperationError(ctx.getNode(), 'SoftOne login returned no companies for this user.', { itemIndex });
    }
    if (!companyId)
        return companies[0];
    const match = companies.find((c) => String(c.COMPANY) === String(companyId));
    if (!match) {
        throw new n8n_workflow_1.NodeOperationError(ctx.getNode(), `Company ${companyId} not accessible for this SoftOne user.`, { itemIndex });
    }
    return match;
}
async function authenticateOnce(ctx, creds, login, company, itemIndex) {
    const body = {
        service: 'authenticate',
        clientID: login.clientID,
        COMPANY: company.COMPANY,
        BRANCH: company.BRANCH,
        MODULE: company.MODULE,
        REFID: company.REFID,
    };
    return (await callJson(ctx, creds, body, itemIndex));
}
async function getSession(ctx, creds, cache, itemIndex) {
    const companyId = creds.defaultCompanyId?.trim() || '';
    const cacheKey = `${creds.host}|${creds.username}|${companyId}`;
    const cached = cache.get(cacheKey);
    if (cached)
        return cached;
    const login = await loginOnce(ctx, creds, itemIndex);
    const company = pickCompany(login, companyId, ctx, itemIndex);
    const auth = await authenticateOnce(ctx, creds, login, company, itemIndex);
    const session = {
        clientID: String(auth.clientID ?? ''),
        appid: String(login.appid ?? ''),
        company,
    };
    cache.set(cacheKey, session);
    return session;
}
// ---------- Misc helpers ----------
function parseJsonParam(ctx, raw, fieldName, itemIndex) {
    const trimmed = (raw ?? '').trim();
    if (!trimmed)
        return {};
    try {
        const parsed = JSON.parse(trimmed);
        if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
            throw new Error('not an object');
        }
        return stripPrototypeKeys(parsed);
    }
    catch (e) {
        throw new n8n_workflow_1.NodeOperationError(ctx.getNode(), `${fieldName} must be a JSON object. ${e.message}`, { itemIndex });
    }
}
function normalizeRows(response) {
    const rows = response.rows;
    if (!Array.isArray(rows) || rows.length === 0)
        return [];
    const fields = Array.isArray(response.fields) ? response.fields : [];
    // SqlData returns row objects directly; getBrowserInfo returns arrays aligned with fields[].name
    if (typeof rows[0] === 'object' && !Array.isArray(rows[0])) {
        return rows;
    }
    if (fields.length === 0) {
        return rows.map((r, i) => ({ [`col_${i}`]: r }));
    }
    const fieldNames = fields.map((f) => String(f.name ?? ''));
    return rows.map((row) => {
        const obj = {};
        for (let i = 0; i < fieldNames.length; i++) {
            obj[fieldNames[i] || `col_${i}`] = row[i];
        }
        return obj;
    });
}
// ---------- Node ----------
class SoftOne {
    constructor() {
        this.description = {
            displayName: 'SoftOne',
            name: 'softOne',
            icon: 'file:softOne.svg',
            group: ['transform'],
            version: 1,
            subtitle: '={{$parameter["operation"] + ": " + $parameter["resource"]}}',
            description: 'Interact with the SoftOne ERP JSON API',
            defaults: { name: 'SoftOne' },
            inputs: ['main'],
            outputs: ['main'],
            credentials: [
                { name: 'softOneApi', required: true, testedBy: 'softOneApiTest' },
            ],
            properties: [
                {
                    displayName: 'Resource',
                    name: 'resource',
                    type: 'options',
                    noDataExpression: true,
                    options: [
                        { name: 'SQL Data', value: 'sqlData' },
                        { name: 'Object', value: 'object' },
                        { name: 'Metadata', value: 'metadata' },
                        { name: 'Report', value: 'report' },
                        { name: 'Custom Endpoint', value: 'endpoint' },
                    ],
                    default: 'sqlData',
                },
                // ---------- SQL Data ----------
                {
                    displayName: 'Operation',
                    name: 'operation',
                    type: 'options',
                    noDataExpression: true,
                    displayOptions: { show: { resource: ['sqlData'] } },
                    options: [
                        {
                            name: 'Run Named SQL',
                            value: 'runNamedSql',
                            action: 'Run a named SoftOne SQL query',
                            description: 'Invoke a server-side SQL by name (SqlData service).',
                        },
                    ],
                    default: 'runNamedSql',
                },
                {
                    displayName: 'SQL Preset',
                    name: 'sqlPreset',
                    type: 'options',
                    displayOptions: { show: { resource: ['sqlData'], operation: ['runNamedSql'] } },
                    options: SQL_PRESETS,
                    default: '__custom__',
                    description: 'Pick a known SQL name or "Custom…" to enter a different value.',
                },
                {
                    displayName: 'Custom SQL Name',
                    name: 'sqlNameCustom',
                    type: 'string',
                    default: '',
                    displayOptions: {
                        show: { resource: ['sqlData'], operation: ['runNamedSql'], sqlPreset: ['__custom__'] },
                    },
                    description: 'SoftOne SqlName.',
                },
                {
                    displayName: 'Param 1',
                    name: 'param1',
                    type: 'string',
                    default: '',
                    displayOptions: { show: { resource: ['sqlData'], operation: ['runNamedSql'] } },
                },
                {
                    displayName: 'Param 2',
                    name: 'param2',
                    type: 'string',
                    default: '',
                    displayOptions: { show: { resource: ['sqlData'], operation: ['runNamedSql'] } },
                },
                {
                    displayName: 'Param 3',
                    name: 'param3',
                    type: 'string',
                    default: '',
                    displayOptions: { show: { resource: ['sqlData'], operation: ['runNamedSql'] } },
                },
                {
                    displayName: 'Split Rows',
                    name: 'splitRows',
                    type: 'boolean',
                    default: true,
                    description: 'Emit one item per row returned. Off = single item with full response.',
                    displayOptions: { show: { resource: ['sqlData'], operation: ['runNamedSql'] } },
                },
                // ---------- Object ----------
                {
                    displayName: 'Operation',
                    name: 'operation',
                    type: 'options',
                    noDataExpression: true,
                    displayOptions: { show: { resource: ['object'] } },
                    options: [
                        { name: 'Get by Key', value: 'getByKey', action: 'Get one record by primary key' },
                        { name: 'List', value: 'list', action: 'List records via getBrowserInfo' },
                        { name: 'List Next Page', value: 'listNext', action: 'Paginate a previous List via reqID' },
                        { name: 'Create', value: 'create', action: 'Create a record (setData)' },
                        { name: 'Update', value: 'update', action: 'Update a record (setData)' },
                        { name: 'Delete', value: 'delete', action: 'Delete a record (delData)' },
                        { name: 'Calculate', value: 'calculate', action: 'Dry-run setData; returns computed values without persisting' },
                    ],
                    default: 'getByKey',
                },
                {
                    displayName: 'Object Type',
                    name: 'objectType',
                    type: 'options',
                    displayOptions: {
                        show: { resource: ['object'], operation: ['getByKey', 'list', 'create', 'update', 'delete', 'calculate'] },
                    },
                    options: OBJECT_PRESETS,
                    default: 'CUSTOMER',
                    description: 'SoftOne OBJECT name.',
                },
                {
                    displayName: 'Custom Object Name',
                    name: 'objectNameCustom',
                    type: 'string',
                    default: '',
                    displayOptions: { show: { resource: ['object'], objectType: ['__custom__'] } },
                },
                {
                    displayName: 'Key',
                    name: 'key',
                    type: 'string',
                    default: '',
                    required: true,
                    displayOptions: { show: { resource: ['object'], operation: ['getByKey', 'update', 'delete'] } },
                    description: 'Primary key of the record.',
                },
                {
                    displayName: 'Key',
                    name: 'key',
                    type: 'string',
                    default: '',
                    displayOptions: { show: { resource: ['object'], operation: ['calculate'] } },
                    description: 'Optional primary key. Omit when calculating fields for a new record.',
                },
                {
                    displayName: 'LOCATEINFO',
                    name: 'locateInfo',
                    type: 'string',
                    default: '',
                    placeholder: 'CUSTOMER:CODE,NAME,AFM;CUSEXTRA:VARCHAR02,DATE01',
                    description: 'Optional. Comma-separated field list per table. Limits the returned payload to the named fields.',
                    displayOptions: { show: { resource: ['object'], operation: ['getByKey', 'create', 'update', 'calculate'] } },
                },
                {
                    displayName: 'Form',
                    name: 'form',
                    type: 'string',
                    default: '',
                    description: 'Optional SoftOne FORM identifier — only needed when the object has multiple forms.',
                    displayOptions: { show: { resource: ['object'], operation: ['getByKey', 'list'] } },
                },
                // List-specific
                {
                    displayName: 'Filter Mode',
                    name: 'filterMode',
                    type: 'options',
                    options: [
                        { name: 'Builder', value: 'builder' },
                        { name: 'Raw', value: 'raw' },
                    ],
                    default: 'builder',
                    displayOptions: { show: { resource: ['object'], operation: ['list'] } },
                },
                {
                    displayName: 'Filters',
                    name: 'filtersBuilder',
                    type: 'fixedCollection',
                    typeOptions: { multipleValues: true, sortable: true },
                    default: {},
                    placeholder: 'Add Condition',
                    description: 'Each condition is AND-joined.',
                    displayOptions: { show: { resource: ['object'], operation: ['list'], filterMode: ['builder'] } },
                    options: [
                        {
                            name: 'conditions',
                            displayName: 'Condition',
                            values: [
                                { displayName: 'Field', name: 'field', type: 'string', default: '', placeholder: 'CUSTOMER.NAME' },
                                {
                                    displayName: 'Operator',
                                    name: 'operator',
                                    type: 'options',
                                    options: [
                                        { name: 'Equals', value: 'equals' },
                                        { name: 'Contains', value: 'contains' },
                                        { name: 'Starts With', value: 'startsWith' },
                                        { name: 'Ends With', value: 'endsWith' },
                                        { name: 'Range (Between)', value: 'range' },
                                        { name: 'In List (OR)', value: 'inList' },
                                        { name: 'Is True', value: 'isTrue' },
                                        { name: 'Is False', value: 'isFalse' },
                                    ],
                                    default: 'equals',
                                },
                                {
                                    displayName: 'Value',
                                    name: 'value',
                                    type: 'string',
                                    default: '',
                                    description: 'For "In List (OR)" separate values with | (pipe). "&", "=", "|" are URL-encoded automatically.',
                                    displayOptions: { hide: { operator: ['range', 'isTrue', 'isFalse'] } },
                                },
                                { displayName: 'From', name: 'valueFrom', type: 'string', default: '', displayOptions: { show: { operator: ['range'] } } },
                                { displayName: 'To', name: 'valueTo', type: 'string', default: '', displayOptions: { show: { operator: ['range'] } } },
                            ],
                        },
                    ],
                },
                {
                    displayName: 'Raw FILTERS',
                    name: 'filters',
                    type: 'string',
                    default: '',
                    displayOptions: { show: { resource: ['object'], operation: ['list'], filterMode: ['raw'] } },
                },
                {
                    displayName: 'Limit',
                    name: 'limit',
                    type: 'number',
                    default: 200,
                    description: 'Rows per page.',
                    displayOptions: { show: { resource: ['object'], operation: ['list', 'listNext'] } },
                },
                {
                    displayName: 'Fetch All',
                    name: 'fetchAll',
                    type: 'boolean',
                    default: false,
                    description: 'Loop getBrowserData until every row up to Max Rows is fetched.',
                    displayOptions: { show: { resource: ['object'], operation: ['list'] } },
                },
                {
                    displayName: 'Max Rows',
                    name: 'maxRows',
                    type: 'number',
                    default: 10000,
                    description: 'Hard ceiling when Fetch All is on.',
                    displayOptions: { show: { resource: ['object'], operation: ['list'], fetchAll: [true] } },
                },
                {
                    displayName: 'Split Rows',
                    name: 'splitRows',
                    type: 'boolean',
                    default: true,
                    description: 'Emit one item per row. Off = single item with {rows, reqID, totalcount, fields, columns}.',
                    displayOptions: { show: { resource: ['object'], operation: ['list', 'listNext'] } },
                },
                {
                    displayName: 'Request ID',
                    name: 'reqID',
                    type: 'string',
                    default: '',
                    required: true,
                    description: 'reqID returned by a previous List call (when Split Rows was off).',
                    displayOptions: { show: { resource: ['object'], operation: ['listNext'] } },
                },
                {
                    displayName: 'Start',
                    name: 'start',
                    type: 'number',
                    default: 0,
                    description: 'Zero-based row offset.',
                    displayOptions: { show: { resource: ['object'], operation: ['listNext'] } },
                },
                // Create / Update / Calculate data
                {
                    displayName: 'Data (JSON)',
                    name: 'dataJson',
                    type: 'json',
                    default: '{}',
                    description: 'Nested SoftOne payload, e.g. {"CUSTOMER":[{"CODE":"100","NAME":"Acme"}], "CUSEXTRA":[{"VARCHAR01":"foo"}]}.',
                    displayOptions: { show: { resource: ['object'], operation: ['create', 'update', 'calculate'] } },
                },
                {
                    displayName: 'Return Saved Data',
                    name: 'returnSaved',
                    type: 'boolean',
                    default: false,
                    description: 'Send VERSION:2 so the response includes the saved record (subject to LOCATEINFO if set).',
                    displayOptions: { show: { resource: ['object'], operation: ['create', 'update'] } },
                },
                // ---------- Metadata ----------
                {
                    displayName: 'Operation',
                    name: 'operation',
                    type: 'options',
                    noDataExpression: true,
                    displayOptions: { show: { resource: ['metadata'] } },
                    options: [
                        { name: 'List Objects', value: 'listObjects', action: 'List all business objects (getObjects)' },
                        { name: 'List Object Tables', value: 'listObjectTables', action: 'List tables of an object (getObjectTables)' },
                        { name: 'List Table Fields', value: 'listTableFields', action: 'List fields of a table (getTableFields)' },
                        { name: 'Get Form Design', value: 'getFormDesign', action: 'Get tables + fields with presentation format' },
                        { name: 'Get Dialog', value: 'getDialog', action: 'Get dialog/browser fields with presentation format' },
                        { name: 'Selector Lookup', value: 'selectorLookup', action: 'getSelectorData — filtered editor lookups' },
                        { name: 'Fields by Key', value: 'fieldsByKey', action: 'selectorFields — named fields by primary key' },
                    ],
                    default: 'listObjects',
                },
                {
                    displayName: 'Object Name',
                    name: 'metaObject',
                    type: 'string',
                    default: 'CUSTOMER',
                    placeholder: 'CUSTOMER',
                    required: true,
                    displayOptions: {
                        show: {
                            resource: ['metadata'],
                            operation: ['listObjectTables', 'listTableFields', 'getFormDesign', 'getDialog'],
                        },
                    },
                },
                {
                    displayName: 'Table Name',
                    name: 'metaTable',
                    type: 'string',
                    default: '',
                    required: true,
                    placeholder: 'CUSTOMER',
                    description: 'Specific table name (from List Object Tables).',
                    displayOptions: { show: { resource: ['metadata'], operation: ['listTableFields'] } },
                },
                {
                    displayName: 'Form',
                    name: 'metaForm',
                    type: 'string',
                    default: '',
                    displayOptions: { show: { resource: ['metadata'], operation: ['getFormDesign'] } },
                },
                {
                    displayName: 'List',
                    name: 'metaList',
                    type: 'string',
                    default: '',
                    description: 'Optional LIST identifier for dialogs.',
                    displayOptions: { show: { resource: ['metadata'], operation: ['getDialog'] } },
                },
                {
                    displayName: 'EDITOR',
                    name: 'selectorEditor',
                    type: 'string',
                    default: '',
                    required: true,
                    placeholder: "1|TRDR|TRDR|SODTYPE=13 AND ISPROSP='0'|",
                    description: 'Editor spec string from SoftOne.',
                    displayOptions: { show: { resource: ['metadata'], operation: ['selectorLookup'] } },
                },
                {
                    displayName: 'Value',
                    name: 'selectorValue',
                    type: 'string',
                    default: '',
                    required: true,
                    displayOptions: { show: { resource: ['metadata'], operation: ['selectorLookup'] } },
                },
                {
                    displayName: 'Table Name',
                    name: 'sfTable',
                    type: 'string',
                    default: 'CUSTOMER',
                    required: true,
                    displayOptions: { show: { resource: ['metadata'], operation: ['fieldsByKey'] } },
                },
                {
                    displayName: 'Key Name',
                    name: 'sfKeyName',
                    type: 'string',
                    default: 'TRDR',
                    required: true,
                    displayOptions: { show: { resource: ['metadata'], operation: ['fieldsByKey'] } },
                },
                {
                    displayName: 'Key Value',
                    name: 'sfKeyValue',
                    type: 'string',
                    default: '',
                    required: true,
                    displayOptions: { show: { resource: ['metadata'], operation: ['fieldsByKey'] } },
                },
                {
                    displayName: 'Result Fields',
                    name: 'sfResultFields',
                    type: 'string',
                    default: 'CODE,NAME',
                    description: 'Comma-separated field list.',
                    required: true,
                    displayOptions: { show: { resource: ['metadata'], operation: ['fieldsByKey'] } },
                },
                // ---------- Report ----------
                {
                    displayName: 'Operation',
                    name: 'operation',
                    type: 'options',
                    noDataExpression: true,
                    displayOptions: { show: { resource: ['report'] } },
                    options: [
                        { name: 'Run Report', value: 'runReport', action: 'Run a SoftOne report and fetch HTML pages' },
                    ],
                    default: 'runReport',
                },
                {
                    displayName: 'Report Object',
                    name: 'reportObject',
                    type: 'string',
                    default: '',
                    required: true,
                    placeholder: 'CUST_ADDR_BOOK',
                    displayOptions: { show: { resource: ['report'], operation: ['runReport'] } },
                },
                {
                    displayName: 'List',
                    name: 'reportList',
                    type: 'string',
                    default: '',
                    displayOptions: { show: { resource: ['report'], operation: ['runReport'] } },
                },
                {
                    displayName: 'Filters',
                    name: 'reportFilters',
                    type: 'string',
                    default: '',
                    description: 'Raw SoftOne FILTERS expression.',
                    displayOptions: { show: { resource: ['report'], operation: ['runReport'] } },
                },
                {
                    displayName: 'Fetch All Pages',
                    name: 'reportFetchAll',
                    type: 'boolean',
                    default: true,
                    description: 'When on, fetch every page of the report.',
                    displayOptions: { show: { resource: ['report'], operation: ['runReport'] } },
                },
                {
                    displayName: 'Page Number',
                    name: 'reportPage',
                    type: 'number',
                    default: 1,
                    displayOptions: { show: { resource: ['report'], operation: ['runReport'], reportFetchAll: [false] } },
                },
                {
                    displayName: 'Split Pages',
                    name: 'reportSplitPages',
                    type: 'boolean',
                    default: true,
                    description: 'Emit one item per page. Off = concatenate into one HTML blob.',
                    displayOptions: { show: { resource: ['report'], operation: ['runReport'], reportFetchAll: [true] } },
                },
                // ---------- Custom Endpoint ----------
                {
                    displayName: 'Operation',
                    name: 'operation',
                    type: 'options',
                    noDataExpression: true,
                    displayOptions: { show: { resource: ['endpoint'] } },
                    options: [
                        {
                            name: 'POST Form',
                            value: 'postForm',
                            action: 'POST a form-encoded body to a custom SoftOne endpoint',
                        },
                    ],
                    default: 'postForm',
                },
                {
                    displayName: 'Endpoint Path',
                    name: 'endpointPath',
                    type: 'string',
                    default: '',
                    required: true,
                    placeholder: '/JS/custom/MyJob',
                    displayOptions: { show: { resource: ['endpoint'] } },
                },
                {
                    displayName: 'Form Data',
                    name: 'formData',
                    type: 'string',
                    default: '',
                    placeholder: 'FINDOC.FINDOC=12345',
                    description: 'Do not include clientID — the node injects it.',
                    displayOptions: { show: { resource: ['endpoint'] } },
                },
                {
                    displayName: 'Response Type',
                    name: 'responseType',
                    type: 'options',
                    options: [
                        { name: 'Binary', value: 'binary' },
                        { name: 'Text', value: 'text' },
                    ],
                    default: 'binary',
                    displayOptions: { show: { resource: ['endpoint'] } },
                },
                {
                    displayName: 'Binary Property',
                    name: 'binaryProperty',
                    type: 'string',
                    default: 'data',
                    displayOptions: { show: { resource: ['endpoint'], responseType: ['binary'] } },
                },
                {
                    displayName: 'File Name',
                    name: 'fileName',
                    type: 'string',
                    default: 'softone-response',
                    displayOptions: { show: { resource: ['endpoint'], responseType: ['binary'] } },
                },
                {
                    displayName: 'MIME Type',
                    name: 'mimeType',
                    type: 'string',
                    default: 'application/octet-stream',
                    displayOptions: { show: { resource: ['endpoint'], responseType: ['binary'] } },
                },
            ],
        };
        this.methods = {
            credentialTest: {
                async softOneApiTest(credential) {
                    const c = credential.data;
                    let url;
                    try {
                        url = validateHost(c.host, Boolean(c.allowUnsafeHost));
                    }
                    catch (e) {
                        return { status: 'Error', message: e.message };
                    }
                    const endpoint = url.toString().replace(/\/$/, '');
                    const loginBody = {
                        service: 'login',
                        username: c.username,
                        password: c.password,
                        appId: c.appId,
                    };
                    if (c.loginDate)
                        loginBody.LOGINDATE = c.loginDate;
                    let loginRes;
                    try {
                        loginRes = (await this.helpers.request({
                            method: 'POST',
                            uri: endpoint,
                            body: loginBody,
                            json: true,
                            timeout: 30000,
                            followRedirect: false,
                            strictSSL: true,
                        }));
                    }
                    catch (e) {
                        return { status: 'Error', message: `Login request failed: ${e.message}` };
                    }
                    if (isSuccessFalse(loginRes)) {
                        return {
                            status: 'Error',
                            message: `Login failed: ${decorateS1Error(loginRes)}`,
                        };
                    }
                    const companies = loginRes.objs ?? [];
                    if (companies.length === 0) {
                        return { status: 'Error', message: 'Login returned no companies for this user.' };
                    }
                    const companyId = c.defaultCompanyId?.trim() ?? '';
                    const company = companyId
                        ? companies.find((x) => String(x.COMPANY) === String(companyId))
                        : companies[0];
                    if (!company) {
                        return {
                            status: 'Error',
                            message: `Company ${companyId} not accessible. Available: ${companies.map((x) => x.COMPANY).join(', ')}.`,
                        };
                    }
                    const authBody = {
                        service: 'authenticate',
                        clientID: loginRes.clientID,
                        COMPANY: company.COMPANY,
                        BRANCH: company.BRANCH,
                        MODULE: company.MODULE,
                        REFID: company.REFID,
                    };
                    let authRes;
                    try {
                        authRes = (await this.helpers.request({
                            method: 'POST',
                            uri: endpoint,
                            body: authBody,
                            json: true,
                            timeout: 30000,
                            followRedirect: false,
                            strictSSL: true,
                        }));
                    }
                    catch (e) {
                        return { status: 'Error', message: `Authenticate request failed: ${e.message}` };
                    }
                    if (isSuccessFalse(authRes)) {
                        return {
                            status: 'Error',
                            message: `Authenticate failed: ${decorateS1Error(authRes)}`,
                        };
                    }
                    return { status: 'OK', message: `Authenticated into company ${company.COMPANY}.` };
                },
            },
        };
    }
    async execute() {
        const items = this.getInputData();
        const returnData = [];
        const creds = (await this.getCredentials('softOneApi'));
        const sessionCache = new Map();
        const resolveObjectName = (i) => {
            const t = this.getNodeParameter('objectType', i);
            const name = t === '__custom__'
                ? this.getNodeParameter('objectNameCustom', i).trim()
                : t;
            if (!name) {
                throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Object name is required.', { itemIndex: i });
            }
            return name;
        };
        for (let i = 0; i < items.length; i++) {
            try {
                const resource = this.getNodeParameter('resource', i);
                const operation = this.getNodeParameter('operation', i);
                // ---------- SQL Data ----------
                if (resource === 'sqlData' && operation === 'runNamedSql') {
                    const session = await getSession(this, creds, sessionCache, i);
                    const preset = this.getNodeParameter('sqlPreset', i);
                    const sqlName = preset === '__custom__'
                        ? this.getNodeParameter('sqlNameCustom', i).trim()
                        : preset;
                    if (!sqlName) {
                        throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'SQL name is required.', { itemIndex: i });
                    }
                    const param1 = this.getNodeParameter('param1', i, '');
                    const param2 = this.getNodeParameter('param2', i, '');
                    const param3 = this.getNodeParameter('param3', i, '');
                    const splitRows = this.getNodeParameter('splitRows', i, true);
                    const body = {
                        service: 'SqlData',
                        clientID: session.clientID,
                        appId: session.appid,
                        SqlName: sqlName,
                    };
                    if (param1)
                        body.param1 = param1;
                    if (param2)
                        body.param2 = param2;
                    if (param3)
                        body.param3 = param3;
                    const response = await callJson(this, creds, body, i);
                    const rows = normalizeRows(response);
                    if (splitRows && rows.length > 0) {
                        for (const row of rows)
                            returnData.push({ json: row });
                    }
                    else {
                        returnData.push({ json: response });
                    }
                    continue;
                }
                // ---------- Object ----------
                if (resource === 'object') {
                    const session = await getSession(this, creds, sessionCache, i);
                    if (operation === 'getByKey') {
                        const objectName = resolveObjectName(i);
                        const key = this.getNodeParameter('key', i);
                        const locateInfo = this.getNodeParameter('locateInfo', i, '').trim();
                        const form = this.getNodeParameter('form', i, '').trim();
                        const body = {
                            service: 'getData',
                            clientID: session.clientID,
                            appId: session.appid,
                            OBJECT: objectName,
                            KEY: key,
                        };
                        if (locateInfo)
                            body.LOCATEINFO = locateInfo;
                        if (form)
                            body.FORM = form;
                        returnData.push({ json: await callJson(this, creds, body, i) });
                        continue;
                    }
                    if (operation === 'list') {
                        const objectName = resolveObjectName(i);
                        const filterMode = this.getNodeParameter('filterMode', i, 'builder');
                        let filters;
                        if (filterMode === 'builder') {
                            const builder = this.getNodeParameter('filtersBuilder', i, {});
                            try {
                                filters = compileFilters(builder.conditions ?? []);
                            }
                            catch (e) {
                                throw new n8n_workflow_1.NodeOperationError(this.getNode(), e.message, { itemIndex: i });
                            }
                        }
                        else {
                            filters = this.getNodeParameter('filters', i, '');
                        }
                        const limit = this.getNodeParameter('limit', i, 200);
                        const form = this.getNodeParameter('form', i, '').trim();
                        const fetchAll = this.getNodeParameter('fetchAll', i, false);
                        const maxRows = this.getNodeParameter('maxRows', i, 10000);
                        const splitRows = this.getNodeParameter('splitRows', i, true);
                        const infoBody = {
                            service: 'getBrowserInfo',
                            clientID: session.clientID,
                            appId: session.appid,
                            OBJECT: objectName,
                            VERSION: 2,
                            LIMIT: limit,
                            FILTERS: filters,
                        };
                        if (form)
                            infoBody.FORM = form;
                        const infoRes = await callJson(this, creds, infoBody, i);
                        const rows = normalizeRows(infoRes);
                        const reqID = String(infoRes.reqID ?? '');
                        const totalcount = Number(infoRes.totalcount ?? rows.length);
                        let collected = rows.slice();
                        if (fetchAll && reqID && totalcount > collected.length) {
                            const cap = Math.min(totalcount, maxRows);
                            while (collected.length < cap) {
                                const dataBody = {
                                    service: 'getBrowserData',
                                    clientID: session.clientID,
                                    appId: session.appid,
                                    reqID,
                                    START: collected.length,
                                    LIMIT: limit,
                                };
                                const dataRes = await callJson(this, creds, dataBody, i);
                                const pageRows = normalizeRows({
                                    ...dataRes,
                                    fields: infoRes.fields,
                                });
                                if (pageRows.length === 0)
                                    break;
                                collected = collected.concat(pageRows);
                                if (pageRows.length < limit)
                                    break;
                            }
                            if (collected.length > maxRows)
                                collected = collected.slice(0, maxRows);
                        }
                        if (splitRows) {
                            for (const row of collected)
                                returnData.push({ json: row });
                        }
                        else {
                            returnData.push({
                                json: {
                                    rows: collected,
                                    reqID,
                                    totalcount,
                                    fields: infoRes.fields ?? null,
                                    columns: infoRes.columns ?? null,
                                    fetchedAll: fetchAll,
                                },
                            });
                        }
                        continue;
                    }
                    if (operation === 'listNext') {
                        const reqID = this.getNodeParameter('reqID', i);
                        const start = this.getNodeParameter('start', i, 0);
                        const limit = this.getNodeParameter('limit', i, 200);
                        const splitRows = this.getNodeParameter('splitRows', i, true);
                        const body = {
                            service: 'getBrowserData',
                            clientID: session.clientID,
                            appId: session.appid,
                            reqID,
                            START: start,
                            LIMIT: limit,
                        };
                        const response = await callJson(this, creds, body, i);
                        const rows = normalizeRows(response);
                        if (splitRows && rows.length > 0) {
                            for (const row of rows)
                                returnData.push({ json: row });
                        }
                        else {
                            returnData.push({
                                json: {
                                    rows,
                                    reqID,
                                    totalcount: Number(response.totalcount ?? rows.length),
                                },
                            });
                        }
                        continue;
                    }
                    if (operation === 'create' || operation === 'update') {
                        const objectName = resolveObjectName(i);
                        const rawData = this.getNodeParameter('dataJson', i, '{}');
                        const data = parseJsonParam(this, rawData, 'Data (JSON)', i);
                        const locateInfo = this.getNodeParameter('locateInfo', i, '').trim();
                        const returnSaved = this.getNodeParameter('returnSaved', i, false);
                        const body = {
                            service: 'setData',
                            clientID: session.clientID,
                            appId: session.appid,
                            OBJECT: objectName,
                            data,
                        };
                        if (operation === 'update') {
                            body.KEY = this.getNodeParameter('key', i);
                        }
                        if (returnSaved)
                            body.VERSION = 2;
                        if (locateInfo)
                            body.LOCATEINFO = locateInfo;
                        returnData.push({ json: await callJson(this, creds, body, i) });
                        continue;
                    }
                    if (operation === 'delete') {
                        const objectName = resolveObjectName(i);
                        const key = this.getNodeParameter('key', i);
                        const body = {
                            service: 'delData',
                            clientID: session.clientID,
                            appId: session.appid,
                            OBJECT: objectName,
                            KEY: key,
                        };
                        returnData.push({ json: await callJson(this, creds, body, i) });
                        continue;
                    }
                    if (operation === 'calculate') {
                        const objectName = resolveObjectName(i);
                        const key = this.getNodeParameter('key', i, '').trim();
                        const rawData = this.getNodeParameter('dataJson', i, '{}');
                        const data = parseJsonParam(this, rawData, 'Data (JSON)', i);
                        const locateInfo = this.getNodeParameter('locateInfo', i, '').trim();
                        const body = {
                            service: 'calculate',
                            clientID: session.clientID,
                            appId: session.appid,
                            OBJECT: objectName,
                            data,
                        };
                        if (key)
                            body.KEY = key;
                        if (locateInfo)
                            body.LOCATEINFO = locateInfo;
                        returnData.push({ json: await callJson(this, creds, body, i) });
                        continue;
                    }
                }
                // ---------- Metadata ----------
                if (resource === 'metadata') {
                    const session = await getSession(this, creds, sessionCache, i);
                    const base = {
                        clientID: session.clientID,
                        appId: session.appid,
                    };
                    if (operation === 'listObjects') {
                        const response = await callJson(this, creds, { ...base, service: 'getObjects' }, i);
                        returnData.push({ json: response });
                        continue;
                    }
                    if (operation === 'listObjectTables') {
                        const objectName = this.getNodeParameter('metaObject', i);
                        const response = await callJson(this, creds, {
                            ...base,
                            service: 'getObjectTables',
                            OBJECT: objectName,
                        }, i);
                        returnData.push({ json: response });
                        continue;
                    }
                    if (operation === 'listTableFields') {
                        const objectName = this.getNodeParameter('metaObject', i);
                        const tableName = this.getNodeParameter('metaTable', i);
                        const response = await callJson(this, creds, {
                            ...base,
                            service: 'getTableFields',
                            OBJECT: objectName,
                            TABLE: tableName,
                        }, i);
                        returnData.push({ json: response });
                        continue;
                    }
                    if (operation === 'getFormDesign') {
                        const objectName = this.getNodeParameter('metaObject', i);
                        const form = this.getNodeParameter('metaForm', i, '').trim();
                        const response = await callJson(this, creds, {
                            ...base,
                            service: 'getFormDesign',
                            OBJECT: objectName,
                            FORM: form,
                        }, i);
                        returnData.push({ json: response });
                        continue;
                    }
                    if (operation === 'getDialog') {
                        const objectName = this.getNodeParameter('metaObject', i);
                        const list = this.getNodeParameter('metaList', i, '').trim();
                        const response = await callJson(this, creds, {
                            ...base,
                            service: 'getDialog',
                            OBJECT: objectName,
                            LIST: list,
                        }, i);
                        returnData.push({ json: response });
                        continue;
                    }
                    if (operation === 'selectorLookup') {
                        const editor = this.getNodeParameter('selectorEditor', i);
                        const value = this.getNodeParameter('selectorValue', i);
                        // getSelectorData returns a bare array, not an object with success/rows
                        const body = {
                            ...base,
                            service: 'getSelectorData',
                            EDITOR: editor,
                            VALUE: value,
                        };
                        const url = validateHost(creds.host, Boolean(creds.allowUnsafeHost));
                        const raw = await this.helpers.httpRequest.call(this, {
                            method: 'POST',
                            url: url.toString().replace(/\/$/, ''),
                            body,
                            json: true,
                            timeout: 90000,
                            disableFollowRedirect: true,
                            skipSslCertificateValidation: false,
                        });
                        returnData.push({ json: { rows: raw } });
                        continue;
                    }
                    if (operation === 'fieldsByKey') {
                        const table = this.getNodeParameter('sfTable', i);
                        const keyName = this.getNodeParameter('sfKeyName', i);
                        const keyValue = this.getNodeParameter('sfKeyValue', i);
                        const resultFields = this.getNodeParameter('sfResultFields', i);
                        const response = await callJson(this, creds, {
                            ...base,
                            service: 'selectorFields',
                            TABLENAME: table,
                            KEYNAME: keyName,
                            KEYVALUE: keyValue,
                            RESULTFIELDS: resultFields,
                        }, i);
                        returnData.push({ json: response });
                        continue;
                    }
                }
                // ---------- Report ----------
                if (resource === 'report' && operation === 'runReport') {
                    const session = await getSession(this, creds, sessionCache, i);
                    const reportObject = this.getNodeParameter('reportObject', i);
                    const list = this.getNodeParameter('reportList', i, '').trim();
                    const filters = this.getNodeParameter('reportFilters', i, '').trim();
                    const fetchAll = this.getNodeParameter('reportFetchAll', i, true);
                    const infoBody = {
                        service: 'getReportInfo',
                        clientID: session.clientID,
                        appId: session.appid,
                        OBJECT: reportObject,
                        LIST: list,
                        FILTERS: filters,
                    };
                    const infoRes = await callJson(this, creds, infoBody, i);
                    const reqID = String(infoRes.reqID ?? '');
                    const npages = Number(infoRes.npages ?? 1);
                    if (!reqID) {
                        throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Report returned no reqID.', { itemIndex: i });
                    }
                    const fetchPage = async (pageNum) => {
                        return callText(this, creds, {
                            service: 'getReportData',
                            clientID: session.clientID,
                            appId: session.appid,
                            reqID,
                            PAGENUM: pageNum,
                        });
                    };
                    if (!fetchAll) {
                        const pageNum = this.getNodeParameter('reportPage', i, 1);
                        const html = await fetchPage(pageNum);
                        returnData.push({
                            json: { reqID, pageNum, npages, html },
                        });
                        continue;
                    }
                    const splitPages = this.getNodeParameter('reportSplitPages', i, true);
                    const pages = [];
                    for (let p = 1; p <= npages; p++) {
                        pages.push(await fetchPage(p));
                    }
                    if (splitPages) {
                        for (let p = 0; p < pages.length; p++) {
                            returnData.push({
                                json: { reqID, pageNum: p + 1, npages, html: pages[p] },
                            });
                        }
                    }
                    else {
                        returnData.push({
                            json: { reqID, npages, html: pages.join('\n') },
                        });
                    }
                    continue;
                }
                // ---------- Custom Endpoint ----------
                if (resource === 'endpoint' && operation === 'postForm') {
                    const url = validateHost(creds.host, Boolean(creds.allowUnsafeHost));
                    const host = url.toString().replace(/\/$/, '');
                    let path;
                    try {
                        path = sanitizeEndpointPath(this.getNodeParameter('endpointPath', i));
                    }
                    catch (e) {
                        throw new n8n_workflow_1.NodeOperationError(this.getNode(), e.message, { itemIndex: i });
                    }
                    const rawFormData = this.getNodeParameter('formData', i, '').trim();
                    const session = await getSession(this, creds, sessionCache, i);
                    const formData = buildFormDataWithClientId(rawFormData, session.clientID);
                    const responseType = this.getNodeParameter('responseType', i);
                    const asBinary = responseType === 'binary';
                    const result = await callRawPost(this, `${host}${path}`, formData, asBinary);
                    if (asBinary) {
                        const binaryProperty = this.getNodeParameter('binaryProperty', i);
                        const fileName = sanitizeFileName(this.getNodeParameter('fileName', i));
                        const mimeType = this.getNodeParameter('mimeType', i) || 'application/octet-stream';
                        const buf = result;
                        const binary = await this.helpers.prepareBinaryData(buf, fileName, mimeType);
                        returnData.push({
                            json: { fileName, size: buf.length, mimeType },
                            binary: { [binaryProperty]: binary },
                        });
                    }
                    else {
                        returnData.push({ json: { response: result } });
                    }
                    continue;
                }
                throw new n8n_workflow_1.NodeOperationError(this.getNode(), `Unsupported resource/operation: ${resource}/${operation}`, { itemIndex: i });
            }
            catch (error) {
                if (this.continueOnFail()) {
                    returnData.push({
                        json: { error: error.message },
                        pairedItem: { item: i },
                    });
                    continue;
                }
                throw error;
            }
        }
        return [returnData];
    }
}
exports.SoftOne = SoftOne;
