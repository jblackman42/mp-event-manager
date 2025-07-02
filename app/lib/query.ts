import { NextResponse, NextRequest } from "next/server";
import { db } from '@/app/lib/db';
import { decrypt } from "./encryption";
import { SessionData } from "./oauth";

type QueryParams = {
    name: string;
    required: boolean;
}

type QueryConfig = {
    query: string;
    params: QueryParams[];
}

export class Query {
    private config: QueryConfig;
    private params: QueryParams[];

    constructor(config: QueryConfig) {
        this.config = config;
        this.params = config.params;
    }

    async executeWithRequest(request: NextRequest) {
        let paramValues: { [key: string]: string } = {};
        
        if (request.method === 'GET') {
            // Extract parameters from URL for GET requests
            const urlParams = request.nextUrl.searchParams;
            
            // Extract all parameters from URL
            this.params.forEach(param => {
                const value = urlParams.get(param.name);
                if (value !== null) {
                    paramValues[param.name] = value;
                }
            });
        } else if (request.method === 'POST') {
            // Extract parameters from JSON body for POST requests
            try {
                const body = await request.json();
                
                // Extract all parameters from body
                this.params.forEach(param => {
                    if (body[param.name] !== undefined) {
                        paramValues[param.name] = String(body[param.name]);
                    }
                });
            } catch (error) {
                return NextResponse.json(
                    { error: 'Invalid JSON body' }, 
                    { status: 400 }
                );
            }
        } else {
            return NextResponse.json(
                { error: `Method ${request.method} not supported` }, 
                { status: 405 }
            );
        }

        // Get session cookie and ensure it exists
        const sessionCookie = request.cookies.get('session')?.value;
        const userParams: {
            userGUID: string | null,
            userRoles: string | null,
            userGroups: string | null
        } = {
            userGUID: null,
            userRoles: null,
            userGroups: null
        };

        if (sessionCookie) {
            const sessionData = await decrypt(sessionCookie);
            const { user_roles, user_groups, sub } = JSON.parse(sessionData) as SessionData;
            userParams.userGUID = sub;
            userParams.userRoles = user_roles;
            userParams.userGroups = user_groups;
        }

        try {
            const result = await this.execute(paramValues, userParams);
            return NextResponse.json(result, { status: 200 });
        } catch (error) {
            console.error('Error executing query:', error);
            return NextResponse.json(
                { error: error instanceof Error ? error.message : 'Unknown error' }, 
                { status: 500 }
            );
        }
    }

    async execute(params: { [key: string]: string } = {}, userParams: { [key: string]: any } = {}): Promise<any> {
        try {
            // Check for required parameters
            const missingParams = this.params
                .filter(param => param.required)
                .filter(param => !params[param.name]);
                
            if (missingParams.length > 0) {
                throw new Error(`Missing required parameters: ${missingParams.map(p => p.name).join(', ')}`);
            }

            const result = await db.queryFromPath(this.config.query, { ...params, ...userParams });
            return result;
        } catch (error) {
            // console.error('Error executing query:', error);
            throw error;
        }
    }
}