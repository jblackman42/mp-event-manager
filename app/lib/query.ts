import { NextResponse, NextRequest } from "next/server";
import { db } from '@/app/lib/db';
import { decrypt } from "./encryption";
import { SessionData } from "./oauth";
import { handleError, createErrorResponse, ValidationError, AuthenticationError, DatabaseError } from "./errors";

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
        try {
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
                    throw new ValidationError('Invalid JSON body');
                }
            } else {
                throw new ValidationError(`Method ${request.method} not supported`);
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
                try {
                    const sessionData = await decrypt(sessionCookie);
                    const { user_roles, user_groups, sub } = JSON.parse(sessionData) as SessionData;
                    userParams.userGUID = sub;
                    userParams.userRoles = user_roles;
                    userParams.userGroups = user_groups;
                } catch (error) {
                    throw new AuthenticationError('Invalid session data');
                }
            }

            const result = await this.execute(paramValues, userParams);
            return NextResponse.json(result, { status: 200 });
        } catch (error) {
            const appError = handleError(error);
            
            // Log the error for debugging
            console.error('Query execution error:', {
                message: appError.message,
                statusCode: appError.statusCode,
                stack: appError.stack,
                path: request.nextUrl.pathname,
                method: request.method
            });

            return NextResponse.json(
                createErrorResponse(appError, request.nextUrl.pathname),
                { status: appError.statusCode }
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
                throw new ValidationError(`Missing required parameters: ${missingParams.map(p => p.name).join(', ')}`);
            }

            const result = await db.queryFromPath(this.config.query, { ...params, ...userParams });
            return result;
        } catch (error) {
            if (error instanceof Error) {
                // Re-throw validation errors as-is
                if (error instanceof ValidationError) {
                    throw error;
                }
                // Wrap database errors
                if (error.message.includes('Database') || error.message.includes('connection')) {
                    throw new DatabaseError(error.message);
                }
            }
            throw error;
        }
    }
}