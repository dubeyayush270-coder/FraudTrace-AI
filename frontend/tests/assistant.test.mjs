/**
 * FraudTrace AI — Investigation Assistant Frontend Automated Test Suite
 * Uses Node's built-in test runner + Vite SSR module loader + react-dom/server
 * so real TypeScript/JSX components are tested offline with zero extra packages.
 */

import assert from 'node:assert/strict'
import test, { after, before } from 'node:test'
import React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { createServer } from 'vite'

let viteServer
let InvestigationAssistantPanel
let AssistantCitationList
let InvoiceInvestigationPanel
let AppComponent
let SafeMarkdown
let assistantHelpers
let apiClient

before(async () => {
  viteServer = await createServer({
    root: new URL('..', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'),
    server: { middlewareMode: true },
    appType: 'custom',
    logLevel: 'silent',
  })

  const panelMod = await viteServer.ssrLoadModule('/src/components/InvestigationAssistantPanel.tsx')
  const invoicePanelMod = await viteServer.ssrLoadModule('/src/components/InvoiceInvestigationPanel.tsx')
  const appMod = await viteServer.ssrLoadModule('/src/App.tsx')
  const mdMod = await viteServer.ssrLoadModule('/src/utils/safeMarkdown.tsx')
  assistantHelpers = await viteServer.ssrLoadModule('/src/utils/assistantHelpers.ts')
  apiClient = await viteServer.ssrLoadModule('/src/services/api.ts')

  InvestigationAssistantPanel = panelMod.default
  AssistantCitationList = panelMod.AssistantCitationList
  InvoiceInvestigationPanel = invoicePanelMod.default
  AppComponent = appMod.default
  SafeMarkdown = mdMod.SafeMarkdown
})

after(async () => {
  if (viteServer) {
    await viteServer.close()
  }
})

const sampleTransactions = [
  {
    id: 16,
    reference: 'PP-CAP-1293669503626341A',
    sender_id: 'SANDBOX_SMOKE_BUYER_01',
    receiver_id: 'FRAUDTRACE_SANDBOX_MERCHANT',
    amount: '1.00',
    currency: 'USD',
    timestamp: '2026-11-12T06:00:00Z',
    risk_score: 10,
    risk_level: 'LOW',
    investigation_status: 'CLEARED',
    created_at: '2026-11-12T06:00:00Z',
  },
]

const sampleTurn = {
  id: 'ast_test_001',
  question: 'Why was transaction #16 flagged?',
  context: {
    transactionId: 16,
    investigationId: 16,
    invoiceId: null,
    accountId: null,
  },
  createdAt: '2026-11-12T06:10:00Z',
  response: {
    answer:
      '## Observed Evidence\nTransaction **#16** triggered `NEW_RECIPIENT` (`10.0/100`).\n\n- Heuristic indicator only.',
    citations: [
      {
        citation_id: 'TXN:16',
        record_type: 'transaction',
        record_id: '16',
        label: 'Transaction #16 (LOW)',
        claim: 'Amount 1.00 USD with risk_score 10.0.',
        excerpt: 'From ACCT_01 to ACCT_02.',
      },
      {
        citation_id: 'EV:15',
        record_type: 'evidence',
        record_id: '15',
        label: 'NEW_RECIPIENT (LOW)',
        claim: 'First recorded transfer to recipient.',
        excerpt: 'Informational indicator; not standalone evidence of fraud.',
      },
    ],
    suggested_questions: ['Check connected accounts next?'],
    limitations: [
      'Heuristic risk scores reflect deterministic rule weights (0-100), not calibrated fraud probabilities.',
    ],
    provider: 'gemini',
    model: 'gemini-3.8-flash',
    request_id: 'ast_test_001',
  },
}

test('1. Chat rendering: empty state & responsive desktop/mobile layout classes', () => {
  const html = renderToStaticMarkup(
    React.createElement(InvestigationAssistantPanel, {
      transactions: sampleTransactions,
      selectedTransactionDetail: null,
      networkOverview: null,
      selectedAccountId: null,
      onContextChange: () => {},
      initialStatus: {
        enabled: true,
        ready: true,
        provider: 'gemini',
        model: 'gemini-3.8-flash',
        data_classification: 'synthetic_demo',
        privacy_policy_ok: true,
        status_code: 'AI_READY',
        message: 'Ready',
      },
    }),
  )

  assert.match(html, /AI Investigation Assistant/)
  assert.match(html, /Ready · gemini \(gemini-3\.8-flash\)/)
  assert.match(html, /Ask about transactions, fraud networks, or invoices/)
  // Mobile & desktop responsive layout classes
  assert.match(html, /grid-cols-1/)
  assert.match(html, /xl:grid-cols-12/)
  assert.match(html, /w-full.*sm:w-auto/)
  assert.match(html, /0\/2000/)
})

test('2. Unavailable / disabled provider states render clear warnings without faking responses', () => {
  const disabledHtml = renderToStaticMarkup(
    React.createElement(InvestigationAssistantPanel, {
      transactions: sampleTransactions,
      selectedTransactionDetail: null,
      networkOverview: null,
      selectedAccountId: null,
      onContextChange: () => {},
      initialStatus: {
        enabled: false,
        ready: false,
        provider: 'gemini',
        model: 'gemini-3.8-flash',
        data_classification: 'synthetic_demo',
        privacy_policy_ok: true,
        status_code: 'AI_DISABLED',
        message: 'AI Investigation Assistant is disabled (AI_ENABLED=false).',
      },
    }),
  )

  assert.match(disabledHtml, /Assistant Disabled \(AI_ENABLED=false\)/)
  assert.match(disabledHtml, /External AI Provider Not Ready/)
  assert.match(disabledHtml, /never fabricates or simulates LLM answers/i)

  const privacyBadge = assistantHelpers.getProviderBadgeMeta({
    enabled: true,
    ready: false,
    provider: 'gemini',
    model: 'gemini-3.8-flash',
    data_classification: 'production',
    privacy_policy_ok: false,
    status_code: 'AI_PRIVACY_POLICY_BLOCKED',
    message: 'Blocked',
  })
  assert.equal(privacyBadge.label, 'Blocked by Data Privacy Policy')
})

test('3. Context selection & context-aware suggested questions', () => {
  const txnPayload = assistantHelpers.buildAssistantChatPayload('  Explain #16  ', {
    transactionId: 16,
    investigationId: 16,
    invoiceId: null,
    accountId: 'ACCT_HUB',
  })
  assert.deepEqual(txnPayload, {
    message: 'Explain #16',
    transaction_id: 16,
    investigation_id: 16,
    account_id: 'ACCT_HUB',
  })

  const invoiceSuggestions = assistantHelpers.buildSuggestedQuestions({
    transactionId: null,
    investigationId: null,
    invoiceId: 7,
    accountId: null,
  })
  assert.ok(invoiceSuggestions.some((s) => s.includes('invoice #7')))

  const html = renderToStaticMarkup(
    React.createElement(InvestigationAssistantPanel, {
      transactions: sampleTransactions,
      selectedTransactionDetail: null,
      networkOverview: {
        total_accounts: 2,
        total_transactions: 1,
        connected_components: 1,
        suspicious_patterns_detected: 0,
        suspicious_account_identifiers: ['SANDBOX_SMOKE_BUYER_01'],
        patterns_summary: {},
      },
      selectedAccountId: 'SANDBOX_SMOKE_BUYER_01',
      contextValue: {
        transactionId: 16,
        investigationId: null,
        invoiceId: null,
        accountId: 'SANDBOX_SMOKE_BUYER_01',
      },
      onContextChange: () => {},
      onInspectAccount: () => {},
      initialStatus: {
        enabled: true,
        ready: true,
        provider: 'gemini',
        model: 'gemini-3.8-flash',
        data_classification: 'synthetic_demo',
        privacy_policy_ok: true,
        status_code: 'AI_READY',
        message: 'Ready',
      },
    }),
  )
  assert.match(html, /#16 · PP-CAP-1293669503626341A/)
  assert.match(html, /Inspect.*SANDBOX_SMOKE_BUYER_01.*in Network Graph/)
})

test('4. Citation rendering, SafeMarkdown XSS protection, and Limitations display', () => {
  const xssHtml = renderToStaticMarkup(
    React.createElement(SafeMarkdown, {
      content: 'Safe **bold** `<script>alert(1)</script>` and <img src=x onerror=alert(2)>',
    }),
  )
  assert.ok(!xssHtml.includes('<script>'))
  assert.ok(!xssHtml.includes('<img'))
  assert.match(xssHtml, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/)

  const turnHtml = renderToStaticMarkup(
    React.createElement(InvestigationAssistantPanel, {
      transactions: sampleTransactions,
      selectedTransactionDetail: null,
      networkOverview: null,
      selectedAccountId: null,
      onContextChange: () => {},
      onSelectTransaction: () => {},
      initialTurns: [sampleTurn],
      initialStatus: {
        enabled: true,
        ready: true,
        provider: 'gemini',
        model: 'gemini-3.8-flash',
        data_classification: 'synthetic_demo',
        privacy_policy_ok: true,
        status_code: 'AI_READY',
        message: 'Ready',
      },
    }),
  )

  assert.match(turnHtml, /Verified Evidence Citations \(2\)/)
  assert.match(turnHtml, /TXN:16/)
  assert.match(turnHtml, /EV:15/)
  assert.match(turnHtml, /Inspect Record/)
  assert.match(turnHtml, /Limitations &amp; Uncertainty Disclosures/)
  assert.match(turnHtml, /not calibrated fraud probabilities/)
})

test('5. Loading and error + retry states render cleanly', () => {
  const html = renderToStaticMarkup(
    React.createElement(InvestigationAssistantPanel, {
      transactions: sampleTransactions,
      selectedTransactionDetail: null,
      networkOverview: null,
      selectedAccountId: null,
      onContextChange: () => {},
      initialLoading: true,
      initialError: 'Gemini API rate limit reached (HTTP 429).',
      initialStatus: {
        enabled: true,
        ready: true,
        provider: 'gemini',
        model: 'gemini-3.8-flash',
        data_classification: 'synthetic_demo',
        privacy_policy_ok: true,
        status_code: 'AI_READY',
        message: 'Ready',
      },
    }),
  )

  assert.match(html, /Retrieving sanitized evidence and generating grounded explanation/)
  assert.match(html, /Assistant Request Failed/)
  assert.match(html, /Gemini API rate limit reached \(HTTP 429\)\./)
  assert.match(html, /Analyzing…/)
})

test('6. Message submission & error propagation via centralized API client', async () => {
  const originalFetch = globalThis.fetch
  const capturedCalls = []

  globalThis.fetch = async (url, init) => {
    capturedCalls.push({ url, init })
    return new Response(JSON.stringify(sampleTurn.response), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })
  }

  try {
    const res = await apiClient.askInvestigationAssistant({
      message: 'Why was transaction #16 flagged?',
      transaction_id: 16,
    })
    assert.equal(capturedCalls.length, 1)
    assert.ok(String(capturedCalls[0].url).endsWith('/api/v1/assistant/chat'))
    assert.equal(capturedCalls[0].init.method, 'POST')
    assert.equal(res.request_id, 'ast_test_001')
    assert.equal(res.citations.length, 2)

    // Verify 503 disabled error surfaces cleanly via ApiClientError
    globalThis.fetch = async () =>
      new Response(JSON.stringify({ detail: 'AI disabled' }), {
        status: 503,
        headers: { 'Content-Type': 'application/json' },
      })

    await assert.rejects(
      () => apiClient.askInvestigationAssistant({ message: 'Test' }),
      (err) => err instanceof apiClient.ApiClientError && err.status === 503 && err.message === 'AI disabled',
    )
  } finally {
    globalThis.fetch = originalFetch
  }
})

function collectButtonClicks(node, out = []) {
  if (!node || typeof node !== 'object') return out
  if (Array.isArray(node)) {
    for (const child of node) collectButtonClicks(child, out)
    return out
  }
  if (node.type === 'button' && typeof node.props?.onClick === 'function') {
    out.push({
      ariaLabel: node.props['aria-label'] ?? '',
      onClick: node.props.onClick,
    })
  }
  if (node.props?.children) {
    collectButtonClicks(node.props.children, out)
  }
  return out
}

test('7. Citation navigation renders Inspect Record ONLY for transaction, account, and invoice citations', () => {
  const citations = [
    {
      citation_id: 'TXN:16',
      record_type: 'transaction',
      record_id: '16',
      label: 'Transaction #16 (LOW)',
      claim: 'Score 10',
      excerpt: 'TXN excerpt',
    },
    {
      citation_id: 'ACCT:ACCT_01',
      record_type: 'account',
      record_id: 'SANDBOX_SMOKE_BUYER_01',
      label: 'Account ACCT_01',
      claim: 'Hub account',
      excerpt: 'Account excerpt',
    },
    {
      citation_id: 'INVOICE:7',
      record_type: 'invoice',
      record_id: '7',
      label: 'Invoice #7 (NEEDS_REVIEW)',
      claim: 'Arithmetic mismatch',
      excerpt: 'Invoice excerpt',
    },
    {
      citation_id: 'INV:16',
      record_type: 'investigation',
      record_id: '16',
      label: 'Investigation #16',
      claim: 'Open case',
      excerpt: 'INV excerpt',
    },
    {
      citation_id: 'EV:15',
      record_type: 'evidence',
      record_id: '15',
      label: 'NEW_RECIPIENT (LOW)',
      claim: 'Indicator',
      excerpt: 'EV excerpt',
    },
    {
      citation_id: 'ML:16',
      record_type: 'ml_anomaly',
      record_id: '16',
      label: 'IsolationForest',
      claim: 'Outlier check',
      excerpt: 'ML excerpt',
    },
    {
      citation_id: 'PAT:1:RAPID_RELAY',
      record_type: 'network_pattern',
      record_id: '1:RAPID_RELAY',
      label: 'RAPID_RELAY',
      claim: 'Pattern lead',
      excerpt: 'PAT excerpt',
    },
    {
      citation_id: 'INVOICE_FINDING:3',
      record_type: 'invoice_finding',
      record_id: '3',
      label: 'TOTAL_MISMATCH',
      claim: 'Mismatch',
      excerpt: 'Finding excerpt',
    },
    {
      citation_id: 'INVOICE_FIELD:7:total_amount',
      record_type: 'invoice_field',
      record_id: '7:total_amount',
      label: 'total_amount',
      claim: '100.00',
      excerpt: 'Field excerpt',
    },
  ]

  const jumpedTxns = []
  const jumpedAccounts = []
  const jumpedInvoices = []

  const element = AssistantCitationList({
    citations,
    onSelectTransaction: (id) => jumpedTxns.push(id),
    onInspectAccount: (acctId) => jumpedAccounts.push(acctId),
    onSelectInvoice: (id) => jumpedInvoices.push(id),
  })
  const html = renderToStaticMarkup(element)

  const inspectButtonMatches = html.match(/Inspect Record →/g) ?? []
  assert.equal(inspectButtonMatches.length, 3)
  assert.match(html, /aria-label="Inspect Record TXN:16"/)
  assert.match(html, /aria-label="Inspect Record ACCT:ACCT_01"/)
  assert.match(html, /aria-label="Inspect Record INVOICE:7"/)
  assert.doesNotMatch(html, /Inspect Record INV:16/)
  assert.doesNotMatch(html, /Inspect Record EV:15/)
  assert.doesNotMatch(html, /Inspect Record ML:16/)
  assert.doesNotMatch(html, /Inspect Record PAT:1:RAPID_RELAY/)
  assert.doesNotMatch(html, /Inspect Record INVOICE_FINDING:3/)
  assert.doesNotMatch(html, /Inspect Record INVOICE_FIELD:7:total_amount/)

  const buttons = collectButtonClicks(element)
  assert.equal(buttons.length, 3)
  for (const btn of buttons) btn.onClick()

  assert.deepEqual(jumpedTxns, [16])
  assert.deepEqual(jumpedAccounts, ['SANDBOX_SMOKE_BUYER_01'])
  assert.deepEqual(jumpedInvoices, [7])
})

test('8. Citation tab resolution handles Assistant tab exits, preserves existing tabs, and renders InvoiceInvestigationPanel cleanly', () => {
  // Assistant tab -> Transaction / Account / Invoice destinations
  assert.equal(assistantHelpers.resolveTabForTransactionInspection('assistant'), 'transactions')
  assert.equal(assistantHelpers.resolveTabForAccountInspection('assistant'), 'network')
  assert.equal(assistantHelpers.resolveTabForInvoiceInspection('assistant'), 'invoices')

  // Preserve existing behavior on current / compatible tabs
  assert.equal(assistantHelpers.resolveTabForTransactionInspection('all'), 'all')
  assert.equal(assistantHelpers.resolveTabForTransactionInspection('transactions'), 'transactions')
  assert.equal(assistantHelpers.resolveTabForTransactionInspection('network'), 'all')
  assert.equal(assistantHelpers.resolveTabForTransactionInspection('invoices'), 'transactions')

  assert.equal(assistantHelpers.resolveTabForAccountInspection('all'), 'all')
  assert.equal(assistantHelpers.resolveTabForAccountInspection('network'), 'network')
  assert.equal(assistantHelpers.resolveTabForAccountInspection('transactions'), 'all')
  assert.equal(assistantHelpers.resolveTabForAccountInspection('invoices'), 'network')

  assert.equal(assistantHelpers.resolveTabForInvoiceInspection('all'), 'invoices')
  assert.equal(assistantHelpers.resolveTabForInvoiceInspection('invoices'), 'invoices')

  // InvoiceInvestigationPanel accepts selectedInvoiceId cleanly without throwing
  const invoiceHtml = renderToStaticMarkup(
    React.createElement(InvoiceInvestigationPanel, {
      selectedInvoiceId: 7,
      onSelectInvoiceChange: () => {},
    }),
  )
  assert.match(invoiceHtml, /Invoice Investigation Details/)
})

test('9. Invoice selection controller handles React StrictMode double-mount, rapid switching, and failure retry', async () => {
  // 9a. StrictMode setup -> cleanup -> setup on non-first INVOICE:1 (pass 1 resolves late)
  {
    const deferreds = new Map()
    let activeView = null
    let isLoading = false
    let errorMsg = null
    let callCount = 0

    const controller = assistantHelpers.createInvoiceSelectionController({
      fetcher: (id) =>
        new Promise((resolve, reject) => {
          callCount += 1
          deferreds.set(`${id}:${callCount}`, { resolve, reject })
        }),
      onStartLoading: () => {
        isLoading = true
        errorMsg = null
      },
      onSuccess: (_id, detail) => {
        activeView = detail
      },
      onError: (_id, msg) => {
        errorMsg = msg
      },
      onFinishLoading: () => {
        isLoading = false
      },
    })

    // StrictMode Pass 1 mounts with selectedInvoiceId = 1
    let cancelled1 = false
    const req1 = controller.startLoad(1, { isCancelled: () => cancelled1 })
    assert.equal(isLoading, true)
    assert.equal(controller.isAlreadyLoaded(1), false)

    // StrictMode Cleanup cancels Pass 1 BEFORE response arrives
    cancelled1 = true
    req1.cancel()

    // StrictMode Pass 2 remounts with selectedInvoiceId = 1
    assert.equal(controller.isLoadedOrInFlight(1), false)
    const cancelled2 = false
    const req2 = controller.startLoad(1, { isCancelled: () => cancelled2 })
    assert.equal(isLoading, true)
    assert.equal(callCount, 2)

    // Pass 2 resolves first
    deferreds.get('1:2').resolve({ id: 1, vendor_name: 'Acme Non-First Invoice' })
    assert.equal(await req2.promise, true)
    assert.equal(isLoading, false)
    assert.equal(errorMsg, null)
    assert.equal(activeView.id, 1)
    assert.equal(controller.getLoadedInvoiceId(), 1)

    // Stale Pass 1 resolves late -> completely ignored
    deferreds.get('1:1').resolve({ id: 99, vendor_name: 'Stale' })
    assert.equal(await req1.promise, false)
    assert.equal(activeView.id, 1)
    assert.equal(isLoading, false)
  }

  // 9b. Rapid switching 1 -> 2 -> 3 with out-of-order delayed responses
  {
    const resolvers = {}
    let activeView = null
    let isLoading = false
    let errorMsg = null

    const controller = assistantHelpers.createInvoiceSelectionController({
      fetcher: (id) =>
        new Promise((resolve, reject) => {
          resolvers[id] = { resolve, reject }
        }),
      onStartLoading: () => {
        isLoading = true
        errorMsg = null
      },
      onSuccess: (_id, detail) => {
        activeView = detail
      },
      onError: (_id, msg) => {
        errorMsg = msg
      },
      onFinishLoading: () => {
        isLoading = false
      },
    })

    const r1 = controller.startLoad(1)
    const r2 = controller.startLoad(2)
    const r3 = controller.startLoad(3)

    // Stale #2 resolves and #1 fails BEFORE #3 resolves -> neither commits nor stops loading
    resolvers[2].resolve({ id: 2 })
    resolvers[1].reject(new Error('Stale network failure'))
    assert.equal(await r2.promise, false)
    assert.equal(await r1.promise, false)
    assert.equal(activeView, null)
    assert.equal(errorMsg, null)
    assert.equal(isLoading, true)

    // Latest #3 resolves -> commits cleanly
    resolvers[3].resolve({ id: 3 })
    assert.equal(await r3.promise, true)
    assert.equal(activeView.id, 3)
    assert.equal(isLoading, false)
    assert.equal(controller.getLoadedInvoiceId(), 3)
  }

  // 9c. Failed fetch followed by retry of same invoice succeeds
  {
    let attempt = 0
    let activeView = null
    let isLoading = false
    let errorMsg = null

    const controller = assistantHelpers.createInvoiceSelectionController({
      fetcher: async (id) => {
        attempt += 1
        if (attempt === 1) {
          throw new Error('Temporary 500')
        }
        return { id, recovered: true }
      },
      onStartLoading: () => {
        isLoading = true
        errorMsg = null
      },
      onSuccess: (_id, detail) => {
        activeView = detail
      },
      onError: (_id, msg) => {
        errorMsg = msg
      },
      onFinishLoading: () => {
        isLoading = false
      },
    })

    assert.equal(await controller.startLoad(2).promise, false)
    assert.equal(isLoading, false)
    assert.equal(errorMsg, 'Temporary 500')
    assert.equal(controller.isAlreadyLoaded(2), false)

    assert.equal(await controller.startLoad(2).promise, true)
    assert.equal(isLoading, false)
    assert.equal(errorMsg, null)
    assert.deepEqual(activeView, { id: 2, recovered: true })
  }
})

test('10. Clear Conversation control renders only with turns and App keeps assistant panel mounted cleanly', () => {
  const emptyHtml = renderToStaticMarkup(
    React.createElement(InvestigationAssistantPanel, {
      transactions: sampleTransactions,
      selectedTransactionDetail: null,
      networkOverview: null,
      selectedAccountId: null,
      onContextChange: () => {},
      initialStatus: {
        enabled: true,
        ready: true,
        provider: 'gemini',
        model: 'gemini-3.7-flash',
        data_classification: 'synthetic_demo',
        external_ai_allowed: true,
        message: 'Ready',
        limitations: [],
      },
      initialTurns: [],
    }),
  )
  assert.doesNotMatch(emptyHtml, /Clear Conversation/)

  const withTurnHtml = renderToStaticMarkup(
    React.createElement(InvestigationAssistantPanel, {
      transactions: sampleTransactions,
      selectedTransactionDetail: null,
      networkOverview: null,
      selectedAccountId: null,
      onContextChange: () => {},
      initialStatus: {
        enabled: true,
        ready: true,
        provider: 'gemini',
        model: 'gemini-3.7-flash',
        data_classification: 'synthetic_demo',
        external_ai_allowed: true,
        message: 'Ready',
        limitations: [],
      },
      initialTurns: [sampleTurn],
    }),
  )
  assert.match(withTurnHtml, /Clear Conversation/)

  const appHtml = renderToStaticMarkup(React.createElement(AppComponent))
  assert.match(appHtml, /aria-label="AI Investigation Assistant"/)
})
