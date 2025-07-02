import { NextRequest } from "next/server";
import { Query } from "@/app/lib/query";

export async function GET(request: NextRequest) {
    return await new Query({
        query: 'events',
        params: [
            { name: 'startDate', required: true },
            { name: 'endDate', required: true }
        ]
    }).executeWithRequest(request);
};

export async function POST(request: NextRequest) {
    return await new Query({
        query: 'events',
        params: [
            { name: 'startDate', required: true },
            { name: 'endDate', required: true }
        ]
    }).executeWithRequest(request);
};