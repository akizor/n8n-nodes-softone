import { IExecuteFunctions, INodeExecutionData, INodeType, INodeTypeDescription, ICredentialTestFunctions, ICredentialsDecrypted, INodeCredentialTestResult } from 'n8n-workflow';
export declare class SoftOne implements INodeType {
    description: INodeTypeDescription;
    methods: {
        credentialTest: {
            softOneApiTest(this: ICredentialTestFunctions, credential: ICredentialsDecrypted): Promise<INodeCredentialTestResult>;
        };
    };
    execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]>;
}
