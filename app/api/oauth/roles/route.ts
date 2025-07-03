import { NextRequest } from "next/server";
import { Query } from "@/app/lib/query";

export async function POST(request: NextRequest) {
    return await new Query({
        query: 'roles',
        params: [
            { name: 'guid', required: true }
        ]
    }).executeWithRequest(request);
};