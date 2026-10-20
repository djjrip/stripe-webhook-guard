import * as fs from 'fs';
import * as path from 'path';

export interface AuditFinding {
  id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'INFO';
  title: string;
  description: string;
  recommendation: string;
  file?: string;
  line?: number;
}

export interface AuditReport {
  scannedFiles: number;
  criticalIssues: number;
  highIssues: number;
  mediumIssues: number;
  infoIssues: number;
  overallScore: number; // 0 - 100
  status: 'FAIL' | 'WARN' | 'PASS';
  findings: AuditFinding[];
}

export class WebhookAuditor {
  /**
   * Scans a file or directory for Stripe webhook vulnerabilities.
   */
  public auditPath(targetPath: string): AuditReport {
    const findings: AuditFinding[] = [];
    let scannedFiles = 0;

    if (!fs.existsSync(targetPath)) {
      throw new Error(`Target path does not exist: ${targetPath}`);
    }

    const stat = fs.statSync(targetPath);
    if (stat.isFile()) {
      scannedFiles = 1;
      this.auditFile(targetPath, findings);
    } else if (stat.isDirectory()) {
      const files = this.collectSourceFiles(targetPath);
      scannedFiles = files.length;
      for (const file of files) {
        this.auditFile(file, findings);
      }
    }

    const criticalCount = findings.filter(f => f.severity === 'CRITICAL').length;
    const highCount = findings.filter(f => f.severity === 'HIGH').length;
    const mediumCount = findings.filter(f => f.severity === 'MEDIUM').length;
    const infoCount = findings.filter(f => f.severity === 'INFO').length;

    // Calculate reliability score (100 base, deductions for flaws)
    let score = 100;
    score -= criticalCount * 35;
    score -= highCount * 20;
    score -= mediumCount * 10;
    score -= infoCount * 2;
    if (score < 0) score = 0;

    const status = criticalCount > 0 ? 'FAIL' : (highCount > 0 || mediumCount > 0) ? 'WARN' : 'PASS';

    return {
      scannedFiles,
      criticalIssues: criticalCount,
      highIssues: highCount,
      mediumIssues: mediumCount,
      infoIssues: infoCount,
      overallScore: score,
      status,
      findings
    };
  }

  /**
   * Scans a single source file for known anti-patterns.
   */
  public auditFile(filePath: string, findings: AuditFinding[]): void {
    const content = fs.readFileSync(filePath, 'utf8');
    const isWebhookFile = /webhook|stripe|payment/i.test(filePath) || /stripe|webhooks/i.test(content);

    if (!isWebhookFile) {
      return;
    }

    const lines = content.split('\n');

    // Next.js App Router source-pattern heuristic. This is intentionally described
    // as a heuristic, not a complete TypeScript AST analysis or proof of exploitability.
    const isAppRouterPostHandler =
      /export\s+(?:async\s+)?function\s+POST\s*\(/i.test(content) ||
      /export\s+const\s+POST\s*=/i.test(content);
    const parsedAppRouterBody = /\b(?:req|request)\.json\s*\(\s*\)/i.test(content);
    const preservesRawRequestBody =
      /\b(?:req|request)\.(?:text|arrayBuffer)\s*\(\s*\)/i.test(content) ||
      /\brawBody\b/i.test(content) ||
      /express\.raw\s*\(/i.test(content);

    if (isWebhookFile && isAppRouterPostHandler && parsedAppRouterBody && !preservesRawRequestBody) {
      const lineIdx = lines.findIndex(l => /\b(?:req|request)\.json\s*\(\s*\)/i.test(l));
      findings.push({
        id: 'NEXTJS_APP_ROUTER_RAW_BODY_RISK',
        severity: 'HIGH',
        title: 'Next.js App Router Parses Webhook JSON Before Raw-Body Verification',
        description: 'Heuristic pattern: a POST handler in a Stripe/webhook-related source file calls req.json() or request.json() without an obvious raw-body read/preservation pattern. Stripe signature verification requires the original request bytes; parsing and re-serializing JSON can change them. Review the full route before treating this as a confirmed vulnerability.',
        recommendation: 'Read the request once as raw text/bytes (for example, await request.text()), verify the stripe-signature with Stripe constructEvent and STRIPE_WEBHOOK_SECRET, then parse/use the verified event. Missing signature or secret must fail closed.',
        file: filePath,
        line: lineIdx >= 0 ? lineIdx + 1 : undefined
      });
    }

    // 1. Raw Body Check: Express.json() used without raw body preservation
    if (/express\.json\(\)/.test(content) || /bodyParser\.json\(\)/.test(content)) {
      const hasRawBodyHandler = /express\.raw\(/i.test(content) || /verify:\s*\(req,\s*res,\s*buf\)/i.test(content) || /rawBody/i.test(content);
      if (!hasRawBodyHandler) {
        const lineIdx = lines.findIndex(l => /express\.json\(\)|bodyParser\.json\(\)/.test(l));
        findings.push({
          id: 'RAW_BODY_CORRUPTED',
          severity: 'CRITICAL',
          title: 'Parsed JSON Replaces Raw Buffer (HMAC Signature Failure)',
          description: 'express.json() or bodyParser.json() parses request bodies before signature verification. Stripe requires the exact raw byte Buffer to compute HMAC SHA-256.',
          recommendation: 'Use express.raw({ type: "application/json" }) on your webhook route or configure express.json({ verify: (req, res, buf) => { req.rawBody = buf; } }).',
          file: filePath,
          line: lineIdx >= 0 ? lineIdx + 1 : undefined
        });
      }
    }

    // 2. Missing Signature Verification
    const hasStripeEvent = /stripe\.webhooks\.constructEvent|verifySignature|StripeWebhookGuard/i.test(content);
    const mentionsStripeRoute = /post\([^)]*webhook/i.test(content) || /router\.post\([^)]*webhook/i.test(content) || (isWebhookFile && isAppRouterPostHandler);
    if (mentionsStripeRoute && !hasStripeEvent) {
      findings.push({
        id: 'MISSING_SIGNATURE_VERIFICATION',
        severity: 'CRITICAL',
        title: 'Unverified Webhook Endpoint (Spoofing & Free Provisioning Exploit)',
        description: 'Stripe webhook route does not invoke signature verification (stripe.webhooks.constructEvent or StripeWebhookGuard). Any attacker can POST fake checkout.session.completed events.',
        recommendation: 'Always verify the stripe-signature header using StripeWebhookGuard or stripe.webhooks.constructEvent with your STRIPE_WEBHOOK_SECRET.',
        file: filePath
      });
    }

    // 3. Database Idempotency Check
    const usesGuard = /StripeWebhookGuard/i.test(content);
    const hasIdempotency = /idempotency|event\.id|events_processed|processed_events|user_rewards|acquiredLock|markCompleted/i.test(content);
    if (hasStripeEvent && !hasIdempotency && !usesGuard) {
      findings.push({
        id: 'MISSING_DATABASE_IDEMPOTENCY',
        severity: 'HIGH',
        title: 'Missing Idempotency Guard (Duplicate Fulfillment Risk)',
        description: 'Stripe guarantees at-least-once delivery and will retry webhooks for up to 72 hours. Processing events without recording event.id causes duplicate fulfillment or double billing.',
        recommendation: 'Record event.id in an idempotency table or Redis lock before executing business logic. Return 200 OK immediately if the event was previously recorded.',
        file: filePath
      });
    }

    // 4. Synchronous Execution & Timeout Risk
    const hasLongSyncWork = /await\s+sendEmail|await\s+dispatchOrder|await\s+generatePdf/i.test(content);
    const returnsAfterWork = /res\.status\(200\)/.test(content) && hasLongSyncWork;
    if (returnsAfterWork && !/queue|bull|temporal|sqs|pg-boss/i.test(content)) {
      findings.push({
        id: 'LONG_RUNNING_SYNC_EXECUTION',
        severity: 'MEDIUM',
        title: 'Synchronous Processing May Trigger Stripe 15s Timeout',
        description: 'Long-running tasks (email dispatch, PDF generation) execute synchronously before returning HTTP 200. Stripe times out after 15-30 seconds and will resend the event.',
        recommendation: 'Acknowledge the webhook with res.status(200).send({ received: true }) immediately after acquiring the idempotency lock, or enqueue the job to an asynchronous worker queue.',
        file: filePath
      });
    }

    // 5. Plaintext Secret Check
    const hasHardcodedSecret = /whsec_[a-zA-Z0-9]{20,}/.test(content);
    if (hasHardcodedSecret && !/whsec_test|whsec_simulated/i.test(content)) {
      findings.push({
        id: 'HARDCODED_WEBHOOK_SECRET',
        severity: 'CRITICAL',
        title: 'Live Stripe Webhook Signing Secret Committed in Source Code',
        description: 'A live whsec_... webhook secret appears hardcoded in source files. Anyone with repository access can forge cryptographically valid webhook payloads.',
        recommendation: 'Move the secret into an environment variable (process.env.STRIPE_WEBHOOK_SECRET) and rotate the secret in your Stripe Dashboard.',
        file: filePath
      });
    }
  }

  private collectSourceFiles(dir: string): string[] {
    const results: string[] = [];
    const entries = fs.readdirSync(dir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!['node_modules', '.git', 'dist', 'build', 'coverage'].includes(entry.name)) {
          results.push(...this.collectSourceFiles(fullPath));
        }
      } else if (entry.isFile()) {
        if (/\.(js|ts|jsx|tsx|mjs|cjs)$/.test(entry.name)) {
          results.push(fullPath);
        }
      }
    }
    return results;
  }
}
