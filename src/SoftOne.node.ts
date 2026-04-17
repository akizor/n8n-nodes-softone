import {
    IDataObject,
    IExecuteFunctions,
    INodeExecutionData,
    INodeType,
    INodeTypeDescription,
    ICredentialTestFunctions,
    ICredentialsDecrypted,
    INodeCredentialTestResult,
    JsonObject,
    NodeApiError,
    NodeOperationError,
} from 'n8n-workflow';
import type { NodeConnectionType } from 'n8n-workflow';

const SQL_PRESETS: { name: string; value: string; description: string }[] = [
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
    { name: 'Custom…', value: '__custom__', description: 'Enter any SqlName manually' },
];

const OBJECT_PRESETS: { name: string; value: string; description: string }[] = [
    { name: 'Product Category (MTRCATEGORY)', value: 'MTRCATEGORY', description: 'Product category master data' },
    { name: 'Manufacturer (MTRMANFCTR)', value: 'MTRMANFCTR', description: 'Manufacturer master data' },
    { name: 'Item / Product (ITEM)', value: 'ITEM', description: 'Product / service master data' },
    { name: 'Customer (CUSTOMER)', value: 'CUSTOMER', description: 'Customer master data' },
    { name: 'Supplier (SUPPLIER)', value: 'SUPPLIER', description: 'Supplier master data' },
    { name: 'Person (PRSN)', value: 'PRSN', description: 'User / person record' },
    { name: 'Sales Document (FINDOC)', value: 'FINDOC', description: 'Invoice / receipt / sale doc' },
    { name: 'Purchase Document (MTRDOC)', value: 'MTRDOC', description: 'NIR / purchase doc' },
    { name: 'Custom…', value: '__custom__', description: 'Enter any SoftOne OBJECT manually' },
];

interface SoftOneCredentials {
    host: string;
    username: string;
    password: string;
    appId: string;
    defaultCompanyId?: string;
    loginDate?: string;
    allowUnsafeHost?: boolean;
}

const SENSITIVE_KEYS = new Set([
    'password', 'Password', 'PASSWORD',
    'username', 'Username', 'USERNAME',
    'clientID', 'clientId', 'CLIENTID',
    'appid', 'appId', 'APPID',
    'pin', 'PIN',
    'sn', 'SN',
]);

const FORBIDDEN_JSON_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function redactSecrets(value: unknown): unknown {
    if (Array.isArray(value)) return value.map(redactSecrets);
    if (value !== null && typeof value === 'object') {
        const out: Record<string, unknown> = {};
        for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
            out[k] = SENSITIVE_KEYS.has(k) ? '***REDACTED***' : redactSecrets(v);
        }
        return out;
    }
    return value;
}

function stripPrototypeKeys(value: unknown): unknown {
    if (Array.isArray(value)) return value.map(stripPrototypeKeys);
    if (value !== null && typeof value === 'object') {
        const out: Record<string, unknown> = {};
        for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
            if (FORBIDDEN_JSON_KEYS.has(k)) continue;
            out[k] = stripPrototypeKeys(v);
        }
        return out;
    }
    return value;
}

function sanitizeFileName(raw: string): string {
    const base = (raw ?? '').toString();
    const noSep = base.replace(/[\\/\x00]/g, '_');
    const noTraversal = noSep
        .split(/[./]/)
        .filter((seg) => seg !== '..' && seg !== '.')
        .join('.');
    const trimmed = noTraversal.replace(/^\.+/, '').trim();
    return trimmed.length > 0 ? trimmed : 'softone-document';
}

function isSuccessFalse(response: unknown): boolean {
    if (response === null || typeof response !== 'object') return false;
    const s = (response as { success?: unknown }).success;
    return s === false || s === 'false' || s === 0 || s === '0';
}

function ipv4ToInt(ip: string): number {
    return ip.split('.').reduce((acc, oct) => (acc << 8) + Number(oct), 0) >>> 0;
}

const PRIVATE_IPV4_RANGES: Array<[number, number]> = [
    [ipv4ToInt('10.0.0.0'),      ipv4ToInt('10.255.255.255')],
    [ipv4ToInt('127.0.0.0'),     ipv4ToInt('127.255.255.255')],
    [ipv4ToInt('169.254.0.0'),   ipv4ToInt('169.254.255.255')],
    [ipv4ToInt('172.16.0.0'),    ipv4ToInt('172.31.255.255')],
    [ipv4ToInt('192.168.0.0'),   ipv4ToInt('192.168.255.255')],
    [ipv4ToInt('0.0.0.0'),       ipv4ToInt('0.255.255.255')],
];

function isForbiddenHost(hostname: string): boolean {
    const h = hostname.toLowerCase();
    if (h === 'localhost' || h === '0.0.0.0' || h === '[::]' || h === '::' || h === '::1') return true;
    if (h.endsWith('.local') || h.endsWith('.internal')) return true;
    if (/^\d+\.\d+\.\d+\.\d+$/.test(h)) {
        const n = ipv4ToInt(h);
        return PRIVATE_IPV4_RANGES.some(([lo, hi]) => n >= lo && n <= hi);
    }
    if (h.startsWith('[') && h.endsWith(']')) {
        const inner = h.slice(1, -1);
        if (inner.startsWith('fe80:') || inner.startsWith('fc') || inner.startsWith('fd')) return true;
        if (inner === '::1') return true;
    }
    return false;
}

function validateHost(host: string, allowUnsafe: boolean): URL {
    let url: URL;
    try {
        url = new URL(host);
    } catch {
        throw new Error(`Invalid SoftOne host URL: ${host}`);
    }
    if (allowUnsafe) return url;
    if (url.protocol !== 'https:') {
        throw new Error(
            `SoftOne host must use https:// (got ${url.protocol}). Enable "Allow Unsafe Host" in the credential only for trusted development endpoints.`,
        );
    }
    if (isForbiddenHost(url.hostname)) {
        throw new Error(
            `SoftOne host ${url.hostname} is on a private/loopback/link-local/metadata range. Enable "Allow Unsafe Host" in the credential if this is intended.`,
        );
    }
    return url;
}

function sanitizeEndpointPath(raw: string): string {
    const trimmed = (raw ?? '').trim();
    if (!trimmed) {
        throw new Error('Endpoint Path is required.');
    }
    if (!trimmed.startsWith('/')) {
        throw new Error('Endpoint Path must start with "/".');
    }
    if (trimmed.includes('?') || trimmed.includes('#')) {
        throw new Error('Endpoint Path must not contain query string or fragment.');
    }
    if (!/^[A-Za-z0-9/_.\-]+$/.test(trimmed)) {
        throw new Error('Endpoint Path contains unsupported characters. Allowed: letters, digits, "/", "_", ".", "-".');
    }
    if (trimmed.split('/').some((seg) => seg === '..')) {
        throw new Error('Endpoint Path must not contain ".." segments.');
    }
    return trimmed;
}

function buildFormDataWithClientId(raw: string, clientID: string): string {
    const stripped = (raw ?? '')
        .split('&')
        .filter((p) => p.length > 0 && !/^clientid=/i.test(p))
        .join('&');
    const injected = `clientID=${encodeURIComponent(clientID)}`;
    return stripped.length > 0 ? `${injected}&${stripped}` : injected;
}

interface SoftOneCompany {
    COMPANY: string;
    BRANCH: string;
    MODULE: string;
    REFID: string;
    [key: string]: unknown;
}

interface LoginResponse {
    success: boolean | string;
    error?: string;
    clientID?: string;
    appid?: string;
    objs?: SoftOneCompany[];
    [key: string]: unknown;
}

interface AuthenticateResponse {
    success: boolean | string;
    error?: string;
    clientID?: string;
    [key: string]: unknown;
}

interface Session {
    clientID: string;
    appid: string;
    company: SoftOneCompany;
    login: LoginResponse;
    auth: AuthenticateResponse;
}

async function callJson(
    ctx: IExecuteFunctions,
    creds: SoftOneCredentials,
    body: IDataObject,
    itemIndex: number,
): Promise<IDataObject> {
    const url = validateHost(creds.host, Boolean(creds.allowUnsafeHost));
    const response = (await ctx.helpers.httpRequest.call(ctx, {
        method: 'POST',
        url: url.toString().replace(/\/$/, ''),
        body,
        json: true,
        timeout: 90000,
        disableFollowRedirect: true,
        skipSslCertificateValidation: false,
    })) as IDataObject;

    if (isSuccessFalse(response)) {
        const safe = redactSecrets(response) as JsonObject;
        throw new NodeApiError(ctx.getNode(), safe, {
            message: `SoftOne API error: ${(response as IDataObject).error ?? 'unknown'}`,
            itemIndex,
        });
    }
    return response ?? {};
}

async function loginOnce(
    ctx: IExecuteFunctions,
    creds: SoftOneCredentials,
    itemIndex: number,
): Promise<LoginResponse> {
    const body: IDataObject = {
        service: 'login',
        username: creds.username,
        password: creds.password,
        appId: creds.appId,
    };
    if (creds.loginDate) {
        body.LOGINDATE = creds.loginDate;
    }
    return (await callJson(ctx, creds, body, itemIndex)) as LoginResponse;
}

function pickCompany(
    login: LoginResponse,
    companyId: string | undefined,
    ctx: IExecuteFunctions,
    itemIndex: number,
): SoftOneCompany {
    const companies = login.objs ?? [];
    if (companies.length === 0) {
        throw new NodeOperationError(
            ctx.getNode(),
            'SoftOne login returned no companies for this user.',
            { itemIndex },
        );
    }
    if (!companyId) return companies[0];
    const match = companies.find((c) => String(c.COMPANY) === String(companyId));
    if (!match) {
        throw new NodeOperationError(
            ctx.getNode(),
            `Company ${companyId} not accessible for this SoftOne user.`,
            { itemIndex },
        );
    }
    return match;
}

async function authenticateOnce(
    ctx: IExecuteFunctions,
    creds: SoftOneCredentials,
    login: LoginResponse,
    company: SoftOneCompany,
    itemIndex: number,
): Promise<AuthenticateResponse> {
    const body: IDataObject = {
        service: 'authenticate',
        clientId: login.clientID,
        COMPANY: company.COMPANY,
        BRANCH: company.BRANCH,
        MODULE: company.MODULE,
        REFID: company.REFID,
    };
    return (await callJson(ctx, creds, body, itemIndex)) as AuthenticateResponse;
}

async function getSession(
    ctx: IExecuteFunctions,
    creds: SoftOneCredentials,
    cache: Map<string, Session>,
    itemIndex: number,
): Promise<Session> {
    const companyId = creds.defaultCompanyId?.trim() || '';
    const cacheKey = `${creds.host}|${creds.username}|${companyId}`;
    const cached = cache.get(cacheKey);
    if (cached) return cached;

    const login = await loginOnce(ctx, creds, itemIndex);
    const company = pickCompany(login, companyId, ctx, itemIndex);
    const auth = await authenticateOnce(ctx, creds, login, company, itemIndex);

    const session: Session = {
        clientID: String(auth.clientID ?? ''),
        appid: String(login.appid ?? ''),
        company,
        login,
        auth,
    };
    cache.set(cacheKey, session);
    return session;
}

function parseJsonParam(
    ctx: IExecuteFunctions,
    raw: string,
    fieldName: string,
    itemIndex: number,
): IDataObject {
    const trimmed = (raw ?? '').trim();
    if (!trimmed) return {};
    try {
        const parsed = JSON.parse(trimmed);
        if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
            throw new Error('not an object');
        }
        return stripPrototypeKeys(parsed) as IDataObject;
    } catch (e) {
        throw new NodeOperationError(
            ctx.getNode(),
            `${fieldName} must be a JSON object. ${(e as Error).message}`,
            { itemIndex },
        );
    }
}

async function callRawPost(
    ctx: IExecuteFunctions,
    url: string,
    postData: string,
    asBinary: boolean,
): Promise<Buffer | string> {
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
        return Buffer.isBuffer(response) ? response : Buffer.from(response as ArrayBuffer);
    }
    return typeof response === 'string' ? response : String(response);
}

export class SoftOne implements INodeType {
    description: INodeTypeDescription = {
        displayName: 'SoftOne',
        name: 'softOne',
        icon: 'file:softOne.svg',
        group: ['transform'],
        version: 1,
        subtitle: '={{$parameter["operation"] + ": " + $parameter["resource"]}}',
        description: 'Interact with the SoftOne ERP JSON API',
        defaults: {
            name: 'SoftOne',
        },
        inputs: ['main' as NodeConnectionType],
        outputs: ['main' as NodeConnectionType],
        credentials: [
            {
                name: 'softOneApi',
                required: true,
                testedBy: 'softOneApiTest',
            },
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
                    { name: 'Custom Endpoint', value: 'endpoint' },
                ],
                default: 'sqlData',
            },

            // -------- SQL Data operations --------
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
                default: 'Tari',
                description: 'Known SoftOne SQL names. Pick "Custom…" to enter a different name.',
            },
            {
                displayName: 'Custom SQL Name',
                name: 'sqlNameCustom',
                type: 'string',
                default: '',
                displayOptions: {
                    show: {
                        resource: ['sqlData'],
                        operation: ['runNamedSql'],
                        sqlPreset: ['__custom__'],
                    },
                },
                description: 'SoftOne SqlName (e.g. scadentec).',
            },
            {
                displayName: 'Param 1',
                name: 'param1',
                type: 'string',
                default: '',
                description: 'Optional param1 passed to the SQL. See preset description.',
                displayOptions: { show: { resource: ['sqlData'], operation: ['runNamedSql'] } },
            },
            {
                displayName: 'Param 2',
                name: 'param2',
                type: 'string',
                default: '',
                description: 'Optional param2 passed to the SQL.',
                displayOptions: { show: { resource: ['sqlData'], operation: ['runNamedSql'] } },
            },
            {
                displayName: 'Param 3',
                name: 'param3',
                type: 'string',
                default: '',
                description: 'Optional param3 passed to the SQL.',
                displayOptions: { show: { resource: ['sqlData'], operation: ['runNamedSql'] } },
            },
            {
                displayName: 'Split Rows',
                name: 'splitRows',
                type: 'boolean',
                default: true,
                description: 'Whether to emit one n8n item per row returned by SoftOne. If off, emits a single item with the full response.',
                displayOptions: { show: { resource: ['sqlData'], operation: ['runNamedSql'] } },
            },

            // -------- Object operations --------
            {
                displayName: 'Operation',
                name: 'operation',
                type: 'options',
                noDataExpression: true,
                displayOptions: { show: { resource: ['object'] } },
                options: [
                    { name: 'Get by Key', value: 'getByKey', action: 'Get an object by its primary key' },
                    { name: 'List', value: 'list', action: 'List objects via getBrowserInfo' },
                    { name: 'Create', value: 'create', action: 'Create an object via setData' },
                    { name: 'Update', value: 'update', action: 'Update an object via setData' },
                ],
                default: 'getByKey',
            },
            {
                displayName: 'Object Type',
                name: 'objectType',
                type: 'options',
                displayOptions: { show: { resource: ['object'] } },
                options: OBJECT_PRESETS,
                default: 'CUSTOMER',
                description: 'SoftOne OBJECT name. Pick "Custom…" to enter a different value.',
            },
            {
                displayName: 'Custom Object Name',
                name: 'objectNameCustom',
                type: 'string',
                default: '',
                displayOptions: {
                    show: { resource: ['object'], objectType: ['__custom__'] },
                },
                description: 'SoftOne OBJECT value (e.g. MTRL).',
            },
            {
                displayName: 'Key',
                name: 'key',
                type: 'string',
                default: '',
                required: true,
                displayOptions: {
                    show: { resource: ['object'], operation: ['getByKey', 'update'] },
                },
                description: 'Primary key of the object.',
            },
            {
                displayName: 'Filters',
                name: 'filters',
                type: 'string',
                default: '',
                description: 'Raw SoftOne FILTERS expression (e.g. "MTRL.SODTYPE=51&MTRL.CODE=ABC123").',
                displayOptions: { show: { resource: ['object'], operation: ['list'] } },
            },
            {
                displayName: 'Start',
                name: 'start',
                type: 'number',
                default: 0,
                displayOptions: { show: { resource: ['object'], operation: ['list'] } },
            },
            {
                displayName: 'Limit',
                name: 'limit',
                type: 'number',
                default: 20,
                displayOptions: { show: { resource: ['object'], operation: ['list'] } },
            },
            {
                displayName: 'Data (JSON)',
                name: 'dataJson',
                type: 'json',
                default: '{}',
                description: 'JSON body for setData. Top-level keys are SoftOne table names (e.g. {"MTRL": {...}, "MTRMANFCTR": {...}}).',
                displayOptions: {
                    show: { resource: ['object'], operation: ['create', 'update'] },
                },
            },

            // -------- Custom Endpoint operations --------
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
                        description:
                            'Send a form-encoded body to a server-side job endpoint configured on the SoftOne instance. The authenticated clientID is auto-injected.',
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
                description:
                    'Absolute path on the SoftOne host (must start with "/"). No query strings, no ".." segments.',
                displayOptions: { show: { resource: ['endpoint'] } },
            },
            {
                displayName: 'Form Data',
                name: 'formData',
                type: 'string',
                default: '',
                placeholder: 'FINDOC.FINDOC=12345',
                description:
                    'URL-encoded body sent to the endpoint. Do not include clientID — the node injects it from the authenticated session.',
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
                description: 'How to interpret the response body.',
                displayOptions: { show: { resource: ['endpoint'] } },
            },
            {
                displayName: 'Binary Property',
                name: 'binaryProperty',
                type: 'string',
                default: 'data',
                description: 'Name of the binary property on the output item.',
                displayOptions: { show: { resource: ['endpoint'], responseType: ['binary'] } },
            },
            {
                displayName: 'File Name',
                name: 'fileName',
                type: 'string',
                default: 'softone-response',
                description: 'File name for the returned binary. Path separators and ".." segments are stripped.',
                displayOptions: { show: { resource: ['endpoint'], responseType: ['binary'] } },
            },
            {
                displayName: 'MIME Type',
                name: 'mimeType',
                type: 'string',
                default: 'application/octet-stream',
                placeholder: 'application/pdf',
                displayOptions: { show: { resource: ['endpoint'], responseType: ['binary'] } },
            },
        ],
    };

    methods = {
        credentialTest: {
            async softOneApiTest(
                this: ICredentialTestFunctions,
                credential: ICredentialsDecrypted,
            ): Promise<INodeCredentialTestResult> {
                const c = credential.data as unknown as SoftOneCredentials;
                let url: URL;
                try {
                    url = validateHost(c.host, Boolean(c.allowUnsafeHost));
                } catch (e) {
                    return { status: 'Error', message: (e as Error).message };
                }
                const endpoint = url.toString().replace(/\/$/, '');
                const loginBody: IDataObject = {
                    service: 'login',
                    username: c.username,
                    password: c.password,
                    appId: c.appId,
                };
                if (c.loginDate) loginBody.LOGINDATE = c.loginDate;

                let loginRes: LoginResponse;
                try {
                    loginRes = (await this.helpers.request({
                        method: 'POST',
                        uri: endpoint,
                        body: loginBody,
                        json: true,
                        timeout: 30000,
                        followRedirect: false,
                        strictSSL: true,
                    })) as LoginResponse;
                } catch (e) {
                    return { status: 'Error', message: `Login request failed: ${(e as Error).message}` };
                }
                if (isSuccessFalse(loginRes)) {
                    return { status: 'Error', message: `Login failed: ${loginRes.error ?? 'unknown'}` };
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

                const authBody: IDataObject = {
                    service: 'authenticate',
                    clientId: loginRes.clientID,
                    COMPANY: company.COMPANY,
                    BRANCH: company.BRANCH,
                    MODULE: company.MODULE,
                    REFID: company.REFID,
                };
                let authRes: AuthenticateResponse;
                try {
                    authRes = (await this.helpers.request({
                        method: 'POST',
                        uri: endpoint,
                        body: authBody,
                        json: true,
                        timeout: 30000,
                        followRedirect: false,
                        strictSSL: true,
                    })) as AuthenticateResponse;
                } catch (e) {
                    return { status: 'Error', message: `Authenticate request failed: ${(e as Error).message}` };
                }
                if (isSuccessFalse(authRes)) {
                    return { status: 'Error', message: `Authenticate failed: ${authRes.error ?? 'unknown'}` };
                }

                return {
                    status: 'OK',
                    message: `Authenticated into company ${company.COMPANY}.`,
                };
            },
        },
    };

    async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
        const items = this.getInputData();
        const returnData: INodeExecutionData[] = [];
        const creds = (await this.getCredentials('softOneApi')) as unknown as SoftOneCredentials;
        const sessionCache = new Map<string, Session>();

        for (let i = 0; i < items.length; i++) {
            try {
                const resource = this.getNodeParameter('resource', i) as string;
                const operation = this.getNodeParameter('operation', i) as string;

                if (resource === 'sqlData' && operation === 'runNamedSql') {
                    const session = await getSession(this, creds, sessionCache, i);
                    const preset = this.getNodeParameter('sqlPreset', i) as string;
                    const sqlName =
                        preset === '__custom__'
                            ? (this.getNodeParameter('sqlNameCustom', i) as string).trim()
                            : preset;
                    if (!sqlName) {
                        throw new NodeOperationError(this.getNode(), 'SQL name is required.', {
                            itemIndex: i,
                        });
                    }
                    const param1 = this.getNodeParameter('param1', i, '') as string;
                    const param2 = this.getNodeParameter('param2', i, '') as string;
                    const param3 = this.getNodeParameter('param3', i, '') as string;
                    const splitRows = this.getNodeParameter('splitRows', i, true) as boolean;

                    const body: IDataObject = {
                        service: 'SqlData',
                        clientId: session.clientID,
                        appId: session.appid,
                        SqlName: sqlName,
                    };
                    if (param1) body.param1 = param1;
                    if (param2) body.param2 = param2;
                    if (param3) body.param3 = param3;

                    const response = await callJson(this, creds, body, i);
                    const rows = Array.isArray((response as IDataObject).rows)
                        ? ((response as IDataObject).rows as IDataObject[])
                        : [];

                    if (splitRows && rows.length > 0) {
                        for (const row of rows) returnData.push({ json: row });
                    } else {
                        returnData.push({ json: response });
                    }
                    continue;
                }

                if (resource === 'object') {
                    const session = await getSession(this, creds, sessionCache, i);
                    const objectType = this.getNodeParameter('objectType', i) as string;
                    const objectName =
                        objectType === '__custom__'
                            ? (this.getNodeParameter('objectNameCustom', i) as string).trim()
                            : objectType;
                    if (!objectName) {
                        throw new NodeOperationError(this.getNode(), 'Object name is required.', {
                            itemIndex: i,
                        });
                    }

                    if (operation === 'getByKey') {
                        const key = this.getNodeParameter('key', i) as string;
                        const body: IDataObject = {
                            service: 'getData',
                            clientId: session.clientID,
                            appId: session.appid,
                            OBJECT: objectName,
                            KEY: key,
                        };
                        returnData.push({ json: await callJson(this, creds, body, i) });
                        continue;
                    }

                    if (operation === 'list') {
                        const filters = this.getNodeParameter('filters', i, '') as string;
                        const start = this.getNodeParameter('start', i, 0) as number;
                        const limit = this.getNodeParameter('limit', i, 20) as number;
                        const body: IDataObject = {
                            service: 'getBrowserInfo',
                            clientId: session.clientID,
                            appId: session.appid,
                            OBJECT: objectName,
                            FILTERS: filters,
                            START: start,
                            LIMIT: limit,
                        };
                        returnData.push({ json: await callJson(this, creds, body, i) });
                        continue;
                    }

                    if (operation === 'create' || operation === 'update') {
                        const rawData = this.getNodeParameter('dataJson', i, '{}') as string;
                        const data = parseJsonParam(this, rawData, 'Data (JSON)', i);
                        const body: IDataObject = {
                            service: 'setData',
                            clientId: session.clientID,
                            appId: session.appid,
                            OBJECT: objectName,
                            data,
                        };
                        if (operation === 'update') {
                            body.KEY = this.getNodeParameter('key', i) as string;
                        }
                        returnData.push({ json: await callJson(this, creds, body, i) });
                        continue;
                    }
                }

                if (resource === 'endpoint' && operation === 'postForm') {
                    const url = validateHost(creds.host, Boolean(creds.allowUnsafeHost));
                    const host = url.toString().replace(/\/$/, '');
                    let path: string;
                    try {
                        path = sanitizeEndpointPath(this.getNodeParameter('endpointPath', i) as string);
                    } catch (e) {
                        throw new NodeOperationError(this.getNode(), (e as Error).message, {
                            itemIndex: i,
                        });
                    }
                    const rawFormData = (this.getNodeParameter('formData', i, '') as string).trim();
                    const session = await getSession(this, creds, sessionCache, i);
                    const formData = buildFormDataWithClientId(rawFormData, session.clientID);
                    const responseType = this.getNodeParameter('responseType', i) as string;
                    const asBinary = responseType === 'binary';
                    const result = await callRawPost(this, `${host}${path}`, formData, asBinary);

                    if (asBinary) {
                        const binaryProperty = this.getNodeParameter('binaryProperty', i) as string;
                        const fileName = sanitizeFileName(
                            this.getNodeParameter('fileName', i) as string,
                        );
                        const mimeType = (this.getNodeParameter('mimeType', i) as string) || 'application/octet-stream';
                        const buf = result as Buffer;
                        const binary = await this.helpers.prepareBinaryData(buf, fileName, mimeType);
                        returnData.push({
                            json: { fileName, size: buf.length, mimeType },
                            binary: { [binaryProperty]: binary },
                        });
                    } else {
                        returnData.push({ json: { response: result as string } });
                    }
                    continue;
                }

                throw new NodeOperationError(
                    this.getNode(),
                    `Unsupported resource/operation: ${resource}/${operation}`,
                    { itemIndex: i },
                );
            } catch (error) {
                if (this.continueOnFail()) {
                    returnData.push({
                        json: { error: (error as Error).message },
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
