import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/client";
import {
  parseCommentEvents,
  verifyWebhookSignature,
} from "@/lib/meta/webhook";
import { processInstagramWebhook } from "@/lib/queue/process-webhook";


export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const mode = searchParams.get("hub.mode");
  const token = searchParams.get("hub.verify_token");
  const challenge = searchParams.get("hub.challenge");

  if (mode === "subscribe" && token === process.env.WEBHOOK_VERIFY_TOKEN) {
    return new NextResponse(challenge, { status: 200 });
  }

  return NextResponse.json(
    { success: false, error: "Verification failed" },
    { status: 403 }
  );
}

export async function POST(request: NextRequest) {
  const rawBody = await request.text();
  const signature = request.headers.get("x-hub-signature-256");

  if (!verifyWebhookSignature(rawBody, signature)) {
    // Record the attempt so a signature mismatch is visible rather than a
    // silent 401. This is the common symptom of FACEBOOK_APP_SECRET being
    // set to the wrong app's secret for the webhook's signing key.
    await prisma.operationalEvent
      .create({
        data: {
          source: "SYSTEM",
          level: "WARNING",
          message: "Webhook signature verification failed",
          payload: {
            hadSignatureHeader: Boolean(signature),
            bodyLength: rawBody.length,
            bodyPreview: rawBody.slice(0, 200),
          },
        },
      })
      .catch(() => {});
    return NextResponse.json(
      { success: false, error: "Invalid signature" },
      { status: 401 }
    );
  }

  let payload: unknown;
  try {
    payload = JSON.parse(rawBody);
  } catch {
    return NextResponse.json(
      { success: false, error: "Invalid JSON" },
      { status: 400 }
    );
  }

  // processInstagramWebhook drops anything whose `object` is not "instagram"
  // before recording it, so a delivery routed through another object — which is
  // how messaging events can arrive for a Facebook Login for Business
  // configuration — is indistinguishable from Meta never sending one. Record
  // the envelope here, ahead of every filter, so that case is visible. Shape
  // only: object, entry ids and which keys each entry carries. No message text.
  const envelope = payload as { object?: unknown; entry?: unknown };
  if (envelope?.object !== "instagram") {
    await prisma.operationalEvent
      .create({
        data: {
          source: "SYSTEM",
          level: "WARNING",
          message: `Webhook ignored: unhandled object "${String(envelope?.object)}"`,
          payload: {
            object: String(envelope?.object),
            entryCount: Array.isArray(envelope?.entry) ? envelope.entry.length : 0,
            entryKeys: Array.isArray(envelope?.entry)
              ? envelope.entry.map((e) => Object.keys(e as object))
              : [],
            bodyPreview: rawBody.slice(0, 600),
          },
        },
      })
      .catch(() => {});
  }

  try {
    await processInstagramWebhook({ payload: payload as Parameters<typeof parseCommentEvents>[0], provider: 'META' });
    return NextResponse.json({ success: true });
  } catch {
    return NextResponse.json({ success: false, error: 'Webhook processing failed' }, { status: 500 });
  }
}
