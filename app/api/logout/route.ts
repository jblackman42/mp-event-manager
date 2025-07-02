import { NextRequest, NextResponse } from "next/server";
import { decrypt } from '@/app/lib/encryption';
import { SessionData } from "@/app/lib/oauth";
import { encodeUrlForm } from "@/app/lib/util"; 
import axios from "axios";


export async function GET(req: NextRequest) {
  const sessionCookie = req.cookies.get("session")?.value;

  if (!sessionCookie) {
    return NextResponse.json({ message: "User Already Logged Out" });
  }

  try {
    const sessionData = await decrypt(sessionCookie);
    const { access_token }: SessionData = JSON.parse(sessionData);

    await axios({
      method: "POST",
      url: `https://my.pureheart.org/ministryplatformapi/oauth/connect/revocation`,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": "Basic ZGV2X3Rlc3Rpbmc6THptVms2c2VSOFhOVXo5NFRLa0dRSE1EUzdFZGhnVUVydG1Ya2Vyd3Y5UjhOOFJLbg=="
      },
      data: encodeUrlForm({
        token: access_token,
        token_type_hint: "access_token"
      })
    });

    const response = NextResponse.redirect(new URL('/'));
    response.headers.set("Set-Cookie", "session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict");
    return response;
  } catch (error) {
    return NextResponse.redirect(new URL('/error?msg=Error in logout', req.url));
  }
}