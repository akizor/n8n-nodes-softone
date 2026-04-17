import {
    ICredentialType,
    INodeProperties,
} from 'n8n-workflow';

export class SoftOneApi implements ICredentialType {
    name = 'softOneApi';
    displayName = 'SoftOne API';
    documentationUrl = 'https://www.softone.gr/';
    properties: INodeProperties[] = [
        {
            displayName: 'Host',
            name: 'host',
            type: 'string',
            default: '',
            placeholder: 'https://sXXXX.softone.gr',
            description:
                'Full base URL of the SoftOne JSON endpoint. The node POSTs directly to this URL.',
            required: true,
        },
        {
            displayName: 'Username',
            name: 'username',
            type: 'string',
            default: '',
            required: true,
        },
        {
            displayName: 'Password',
            name: 'password',
            type: 'string',
            typeOptions: {
                password: true,
            },
            default: '',
            required: true,
        },
        {
            displayName: 'App ID',
            name: 'appId',
            type: 'string',
            default: '',
            description: 'SoftOne application identifier used for login.',
            required: true,
        },
        {
            displayName: 'Company ID',
            name: 'defaultCompanyId',
            type: 'string',
            default: '',
            description:
                'SoftOne COMPANY code used during authenticate. Leave empty to use the first company returned by login. To use a different company, create a separate credential.',
        },
        {
            displayName: 'Login Date',
            name: 'loginDate',
            type: 'string',
            default: '',
            placeholder: 'YYYY-12-31',
            description:
                'Optional LOGINDATE used to log into a specific fiscal year (e.g. 2024-12-31). Leave empty for the current year. To use a different fiscal year, create a separate credential.',
        },
        {
            displayName: 'Allow Unsafe Host',
            name: 'allowUnsafeHost',
            type: 'boolean',
            default: false,
            description:
                'Allow non-HTTPS hosts or private/loopback/link-local/metadata addresses. Keep off in production; enable only for development or an explicitly trusted internal endpoint.',
        },
    ];
}
