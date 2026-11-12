/**
 * InvoiceInvestigationPanel Component
 * Handles PDF/PNG/JPEG invoice uploads (client + server validation), extraction status
 * and honest OCR availability display, separated extracted vs. user-corrected fields,
 * severity-tagged deterministic findings, and persisted invoice investigation history.
 */

import { useCallback, useEffect, useRef, useState } from 'react'
import type { ChangeEvent, DragEvent } from 'react'
import {
  ApiClientError,
  analyzeInvoice,
  fetchInvoiceDetail,
  fetchInvoices,
} from '../services/api'
import type {
  ExtractedFieldMetadata,
  InvoiceAnalyzeResponse,
  InvoiceDetailResponse,
  InvoiceFindingResponse,
  InvoiceSummaryResponse,
} from '../types/api'
import { formatTimestamp, getRiskBadgeClasses } from '../utils/formatters'
import {
  type StartedInvoiceRequest,
  createInvoiceSelectionController,
} from '../utils/assistantHelpers'

const MAX_UPLOAD_BYTES = 10 * 1024 * 1024 // 10 MB
const ALLOWED_EXTENSIONS = ['.pdf', '.png', '.jpg', '.jpeg']

const FIELD_LABELS: Record<string, string> = {
  vendor_name: 'Vendor / Supplier',
  invoice_number: 'Invoice Number',
  invoice_date: 'Invoice Date',
  due_date: 'Due Date',
  currency: 'Currency',
  subtotal: 'Subtotal',
  tax: 'Tax',
  total_amount: 'Total Amount',
  po_number: 'PO / Reference',
}

interface ActiveInvoiceView {
  invoice: InvoiceSummaryResponse
  fields: ExtractedFieldMetadata[]
  findings: InvoiceFindingResponse[]
  extractionNote: string | null
}

function fromAnalyzeResponse(res: InvoiceAnalyzeResponse): ActiveInvoiceView {
  return {
    invoice: res.invoice,
    fields: res.fields,
    findings: res.findings,
    extractionNote: res.extraction_note,
  }
}

function fromDetailResponse(res: InvoiceDetailResponse): ActiveInvoiceView {
  return {
    invoice: res,
    fields: res.fields,
    findings: res.findings,
    extractionNote: res.extraction_note ?? null,
  }
}

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
}

function getInvestigationStatusMeta(status: string): {
  label: string
  classes: string
} {
  switch (status.toUpperCase()) {
    case 'NO_FINDINGS':
      return {
        label: 'Checks Completed — No Findings',
        classes: 'border-emerald-500/40 bg-emerald-500/15 text-emerald-300',
      }
    case 'NEEDS_REVIEW':
      return {
        label: 'Findings Require Review',
        classes: 'border-amber-500/40 bg-amber-500/15 text-amber-300',
      }
    case 'INCOMPLETE_EXTRACTION':
    default:
      return {
        label: 'Extraction Unavailable / Incomplete',
        classes: 'border-orange-500/40 bg-orange-500/15 text-orange-300',
      }
  }
}

function getFieldStatusClasses(status: string): string {
  switch (status.toUpperCase()) {
    case 'EXTRACTED':
      return 'border-sky-500/35 bg-sky-500/10 text-sky-300'
    case 'USER_CORRECTED':
      return 'border-indigo-500/40 bg-indigo-500/15 text-indigo-300'
    case 'OCR_UNAVAILABLE':
      return 'border-amber-500/35 bg-amber-500/10 text-amber-300'
    default:
      return 'border-slate-700 bg-slate-800/70 text-slate-400'
  }
}

function formatFindingCode(code: string): string {
  return code.replaceAll('_', ' ')
}

function validateClientFile(file: File): string | null {
  const lower = file.name.toLowerCase()
  const hasAllowedExt = ALLOWED_EXTENSIONS.some((ext) => lower.endsWith(ext))
  if (!hasAllowedExt) {
    return 'Unsupported file extension. Upload a PDF, PNG, or JPG/JPEG invoice.'
  }
  if (file.size === 0) {
    return 'Selected file is empty (0 bytes).'
  }
  if (file.size > MAX_UPLOAD_BYTES) {
    return 'Selected file exceeds the 10 MB maximum upload limit.'
  }
  return null
}

interface InvoiceInvestigationPanelProps {
  selectedInvoiceId?: number | null
  onSelectInvoiceChange?: (invoiceId: number) => void
  onAskAssistant?: (invoiceId: number) => void
}

export default function InvoiceInvestigationPanel({
  selectedInvoiceId = null,
  onSelectInvoiceChange,
  onAskAssistant,
}: InvoiceInvestigationPanelProps = {}) {
  const fileInputRef = useRef<HTMLInputElement | null>(null)
  const detailsSectionRef = useRef<HTMLElement | null>(null)
  const selectedInvoiceIdRef = useRef<number | null>(selectedInvoiceId)
  const isMountedRef = useRef(true)

  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [clientError, setClientError] = useState<string | null>(null)
  const [uploadError, setUploadError] = useState<string | null>(null)
  const [detailError, setDetailError] = useState<string | null>(null)
  const [isDragging, setIsDragging] = useState(false)
  const [isUploading, setIsUploading] = useState(false)

  // Optional user-entered corrections kept cleanly separate from extracted fields
  const [showOptions, setShowOptions] = useState(false)
  const [rejectDuplicates, setRejectDuplicates] = useState(false)
  const [corrections, setCorrections] = useState<Record<string, string>>({})

  // Active investigation & persisted history
  const [activeView, setActiveView] = useState<ActiveInvoiceView | null>(null)
  const [history, setHistory] = useState<InvoiceSummaryResponse[]>([])
  const [historyTotal, setHistoryTotal] = useState(0)
  const [isHistoryLoading, setIsHistoryLoading] = useState(true)
  const [isDetailLoading, setIsDetailLoading] = useState(false)
  const [historyError, setHistoryError] = useState<string | null>(null)

  const detailControllerRef = useRef<ReturnType<
    typeof createInvoiceSelectionController<InvoiceDetailResponse>
  > | null>(null)

  const getDetailController = useCallback(() => {
    if (!detailControllerRef.current) {
      detailControllerRef.current = createInvoiceSelectionController<InvoiceDetailResponse>({
        fetcher: fetchInvoiceDetail,
        isMounted: () => isMountedRef.current,
        onStartLoading: () => {
          setIsDetailLoading(true)
          setDetailError(null)
        },
        onSuccess: (_invoiceId, detail) => {
          setActiveView(fromDetailResponse(detail))
          setDetailError(null)
        },
        onError: (_invoiceId, message) => {
          setDetailError(message)
        },
        onFinishLoading: () => {
          setIsDetailLoading(false)
        },
      })
    }
    return detailControllerRef.current
  }, [])

  const scrollDetailsIntoView = useCallback(() => {
    window.setTimeout(() => {
      detailsSectionRef.current?.scrollIntoView({
        behavior: 'smooth',
        block: 'nearest',
      })
    }, 60)
  }, [])

  useEffect(() => {
    isMountedRef.current = true
    return () => {
      isMountedRef.current = false
    }
  }, [])

  const loadHistory = useCallback(async (selectFirstIfEmpty = false) => {
    setIsHistoryLoading(true)
    setHistoryError(null)
    try {
      const res = await fetchInvoices(20, 0)
      if (!isMountedRef.current) return
      setHistory(res.items)
      setHistoryTotal(res.total)
      if (selectFirstIfEmpty && res.items.length > 0) {
        await getDetailController().startLoad(res.items[0].id).promise
      }
    } catch (err) {
      if (!isMountedRef.current) return
      setHistoryError(
        err instanceof Error ? err.message : 'Unable to load invoice investigation history.',
      )
    } finally {
      if (isMountedRef.current) {
        setIsHistoryLoading(false)
      }
    }
  }, [getDetailController])

  const handleSelectHistoryItem = useCallback(
    async (invoiceId: number, notifyParent = true) => {
      if (notifyParent) {
        onSelectInvoiceChange?.(invoiceId)
      }
      await getDetailController().startLoad(invoiceId).promise
    },
    [getDetailController, onSelectInvoiceChange],
  )

  useEffect(() => {
    selectedInvoiceIdRef.current = selectedInvoiceId
  }, [selectedInvoiceId])

  useEffect(() => {
    let active = true
    let defaultDetailReq: StartedInvoiceRequest | null = null
    const controller = getDetailController()

    fetchInvoices(20, 0)
      .then(async (res) => {
        if (!active) return
        setHistory(res.items)
        setHistoryTotal(res.total)
        setHistoryError(null)
        if (
          selectedInvoiceIdRef.current === null &&
          controller.getLoadedInvoiceId() === null &&
          controller.getInFlightInvoiceId() === null &&
          res.items.length > 0
        ) {
          defaultDetailReq = controller.startLoad(res.items[0].id, {
            isCancelled: () => !active || selectedInvoiceIdRef.current !== null,
          })
          await defaultDetailReq.promise
        }
      })
      .catch((err) => {
        if (!active) return
        setHistoryError(
          err instanceof Error ? err.message : 'Unable to load invoice investigation history.',
        )
      })
      .finally(() => {
        if (active) {
          setIsHistoryLoading(false)
        }
      })

    return () => {
      active = false
      defaultDetailReq?.cancel()
    }
  }, [getDetailController])

  useEffect(() => {
    if (selectedInvoiceId === null || selectedInvoiceId === undefined) return
    const controller = getDetailController()
    if (controller.isLoadedOrInFlight(selectedInvoiceId)) {
      if (controller.isAlreadyLoaded(selectedInvoiceId)) {
        setIsDetailLoading(false)
        setDetailError(null)
      }
      scrollDetailsIntoView()
      return
    }

    let cancelled = false
    const req = controller.startLoad(selectedInvoiceId, {
      isCancelled: () => cancelled,
    })
    void req.promise.then((didLoad) => {
      if (!cancelled && didLoad) {
        scrollDetailsIntoView()
      }
    })

    return () => {
      cancelled = true
      req.cancel()
    }
  }, [getDetailController, scrollDetailsIntoView, selectedInvoiceId])

  const handleSelectFile = (file: File | null) => {
    setUploadError(null)
    if (!file) {
      setSelectedFile(null)
      setClientError(null)
      return
    }
    const validationErr = validateClientFile(file)
    if (validationErr) {
      setSelectedFile(null)
      setClientError(validationErr)
      return
    }
    setClientError(null)
    setSelectedFile(file)
  }

  const handleInputChange = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0] ?? null
    handleSelectFile(file)
  }

  const handleDrop = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault()
    event.stopPropagation()
    setIsDragging(false)
    const file = event.dataTransfer.files?.[0] ?? null
    handleSelectFile(file)
  }

  const handleUploadSubmit = async () => {
    if (!selectedFile) {
      setClientError('Choose a PDF, PNG, or JPG/JPEG invoice document first.')
      return
    }
    const validationErr = validateClientFile(selectedFile)
    if (validationErr) {
      setClientError(validationErr)
      return
    }

    const cleanCorrections: Record<string, string> = {}
    for (const [k, v] of Object.entries(corrections)) {
      const trimmed = v.trim()
      if (trimmed.length > 0) {
        cleanCorrections[k] = trimmed
      }
    }

    setIsUploading(true)
    setClientError(null)
    setUploadError(null)
    try {
      const response = await analyzeInvoice(selectedFile, {
        rejectDuplicates,
        corrections: cleanCorrections,
      })
      getDetailController().markLoaded(response.invoice.id)
      setDetailError(null)
      onSelectInvoiceChange?.(response.invoice.id)
      setActiveView(fromAnalyzeResponse(response))
      setSelectedFile(null)
      if (fileInputRef.current) {
        fileInputRef.current.value = ''
      }
      await loadHistory(false)
    } catch (err) {
      if (err instanceof ApiClientError) {
        setUploadError(err.message)
      } else {
        setUploadError(
          err instanceof Error ? err.message : 'Invoice upload and analysis failed.',
        )
      }
    } finally {
      setIsUploading(false)
    }
  }

  const statusMeta = activeView
    ? getInvestigationStatusMeta(activeView.invoice.investigation_status)
    : null

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
        {/* Left: Invoice Upload & Extraction Controls */}
        <section className="xl:col-span-5 rounded-xl border border-slate-800 bg-[#0D1424] p-5">
          <div className="flex items-start justify-between gap-2">
            <div>
              <h2 className="text-base font-semibold text-white">
                Invoice Investigation Upload
              </h2>
              <p className="mt-1 text-xs text-slate-400">
                Upload PDF (up to 5 pages), PNG, or JPG/JPEG (max 10 MB). Documents are validated by magic signature and never persisted on disk.
              </p>
            </div>
            <span className="rounded border border-slate-700 bg-slate-800/80 px-2 py-0.5 text-[10px] font-medium uppercase tracking-wider text-slate-300">
              PyMuPDF + Checks
            </span>
          </div>

          {/* Drag & Drop + File Picker */}
          <div
            onDragOver={(e) => {
              e.preventDefault()
              setIsDragging(true)
            }}
            onDragLeave={(e) => {
              e.preventDefault()
              setIsDragging(false)
            }}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            role="button"
            tabIndex={0}
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault()
                fileInputRef.current?.click()
              }
            }}
            className={`mt-4 flex cursor-pointer flex-col items-center justify-center rounded-lg border-2 border-dashed px-4 py-6 text-center transition ${
              isDragging
                ? 'border-sky-400 bg-sky-500/10'
                : 'border-slate-700 bg-[#090E1A] hover:border-slate-500'
            }`}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept=".pdf,.png,.jpg,.jpeg,application/pdf,image/png,image/jpeg"
              onChange={handleInputChange}
              className="hidden"
              aria-label="Choose invoice document"
            />
            <p className="text-sm font-medium text-slate-200">
              {selectedFile ? selectedFile.name : 'Drop invoice document here, or click to browse'}
            </p>
            <p className="mt-1 text-xs text-slate-400">
              {selectedFile
                ? `${formatFileSize(selectedFile.size)} · Ready to analyze`
                : 'Accepted: .pdf (text-based), .png, .jpg, .jpeg'}
            </p>
          </div>

          {clientError && (
            <div
              role="alert"
              className="mt-3 rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-xs text-red-200"
            >
              {clientError}
            </div>
          )}

          {uploadError && (
            <div
              role="alert"
              className="mt-3 rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-xs text-red-200"
            >
              <span className="font-semibold">Upload Rejected: </span>
              {uploadError}
            </div>
          )}

          {/* Optional Corrections & Submission Policy */}
          <div className="mt-4">
            <button
              type="button"
              onClick={() => setShowOptions((prev) => !prev)}
              className="text-xs font-medium text-sky-300 hover:text-sky-200"
            >
              {showOptions
                ? '▾ Hide Optional Reviewer Corrections & Policy'
                : '▸ Add Optional Reviewer Corrections / Duplicate Policy'}
            </button>

            {showOptions && (
              <div className="mt-3 space-y-3 rounded-lg border border-slate-800 bg-[#090E1A] p-3 text-xs">
                <p className="text-[11px] text-slate-400">
                  Manual values are stored cleanly under <code className="text-slate-200">corrected_value</code> and never overwrite raw <code className="text-slate-200">extracted_value</code>.
                </p>

                <label className="flex items-center gap-2 text-slate-300">
                  <input
                    type="checkbox"
                    checked={rejectDuplicates}
                    onChange={(e) => setRejectDuplicates(e.target.checked)}
                    className="rounded border-slate-600 bg-slate-900 text-sky-500"
                  />
                  Reject duplicate vendor + invoice number with HTTP 409 instead of flagging
                </label>

                <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                  {(
                    [
                      ['vendor_name', 'Vendor Name'],
                      ['invoice_number', 'Invoice Number'],
                      ['invoice_date', 'Invoice Date (YYYY-MM-DD)'],
                      ['due_date', 'Due Date (YYYY-MM-DD)'],
                      ['currency', 'Currency (ISO, e.g. USD)'],
                      ['subtotal', 'Subtotal'],
                      ['tax', 'Tax'],
                      ['total_amount', 'Total Amount'],
                      ['po_number', 'PO Number'],
                    ] as const
                  ).map(([key, label]) => (
                    <label key={key} className="block">
                      <span className="mb-1 block text-[11px] text-slate-400">{label}</span>
                      <input
                        type="text"
                        value={corrections[key] ?? ''}
                        onChange={(e) =>
                          setCorrections((prev) => ({ ...prev, [key]: e.target.value }))
                        }
                        placeholder="Optional override"
                        className="w-full rounded border border-slate-700 bg-[#0D1424] px-2.5 py-1.5 text-xs text-slate-100 placeholder:text-slate-600 focus:border-sky-500 focus:outline-none"
                      />
                    </label>
                  ))}
                </div>
              </div>
            )}
          </div>

          <div className="mt-4 flex flex-wrap items-center gap-2">
            <button
              type="button"
              disabled={!selectedFile || isUploading}
              onClick={() => void handleUploadSubmit()}
              className="flex-1 rounded-lg bg-sky-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-sky-500 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {isUploading ? 'Validating & Investigating…' : 'Analyze Invoice'}
            </button>
            {selectedFile && (
              <button
                type="button"
                disabled={isUploading}
                onClick={() => {
                  handleSelectFile(null)
                  if (fileInputRef.current) fileInputRef.current.value = ''
                }}
                className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-xs text-slate-300 hover:border-slate-500"
              >
                Clear
              </button>
            )}
          </div>
        </section>

        {/* Right: Invoice History */}
        <section className="xl:col-span-7 rounded-xl border border-slate-800 bg-[#0D1424] p-5">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 className="text-base font-semibold text-white">
                Invoice Investigation History
              </h2>
              <p className="mt-0.5 text-xs text-slate-400">
                Persisted metadata and deterministic findings ({historyTotal} total record
                {historyTotal === 1 ? '' : 's'}).
              </p>
            </div>
            <button
              type="button"
              disabled={isHistoryLoading}
              onClick={() => void loadHistory(false)}
              className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs font-medium text-slate-200 hover:border-sky-500/60 hover:text-sky-300 disabled:opacity-50"
            >
              {isHistoryLoading ? 'Loading…' : 'Refresh History'}
            </button>
          </div>

          {historyError && (
            <div className="mt-3 rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-xs text-red-200">
              {historyError}
            </div>
          )}

          {isHistoryLoading && history.length === 0 ? (
            <div className="mt-6 rounded-lg border border-slate-800 bg-[#090E1A] p-6 text-center text-xs text-slate-400">
              Loading invoice investigation history…
            </div>
          ) : history.length === 0 ? (
            <div className="mt-6 rounded-lg border border-slate-800 bg-[#090E1A] p-6 text-center text-xs text-slate-400">
              No invoice investigations stored yet. Upload a PDF, PNG, or JPEG invoice on the left to begin.
            </div>
          ) : (
            <div className="mt-4 overflow-x-auto">
              <table className="min-w-full divide-y divide-slate-800 text-left text-xs">
                <thead>
                  <tr className="text-[11px] uppercase tracking-wider text-slate-400">
                    <th className="py-2 pr-3 font-semibold">Document</th>
                    <th className="py-2 px-3 font-semibold">Vendor / Invoice #</th>
                    <th className="py-2 px-3 font-semibold">Total</th>
                    <th className="py-2 px-3 font-semibold">Extraction</th>
                    <th className="py-2 px-3 font-semibold">Review Status</th>
                    <th className="py-2 pl-3 font-semibold text-right">Findings</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70">
                  {history.map((item) => {
                    const isSelected = activeView?.invoice.id === item.id
                    const itemMeta = getInvestigationStatusMeta(item.investigation_status)
                    return (
                      <tr
                        key={item.id}
                        onClick={() => void handleSelectHistoryItem(item.id)}
                        className={`cursor-pointer transition ${
                          isSelected
                            ? 'bg-sky-500/10'
                            : 'hover:bg-slate-800/40'
                        }`}
                      >
                        <td className="py-2.5 pr-3">
                          <div className="font-medium text-slate-100">
                            {item.original_filename}
                          </div>
                          <div className="text-[11px] text-slate-500">
                            #{item.id} · {item.file_type} · {formatTimestamp(item.created_at)}
                          </div>
                        </td>
                        <td className="py-2.5 px-3">
                          <div className="text-slate-200">
                            {item.vendor_name ?? (
                              <span className="italic text-slate-500">Missing vendor</span>
                            )}
                          </div>
                          <div className="font-mono text-[11px] text-slate-400">
                            {item.invoice_number ?? 'No invoice #'}
                          </div>
                        </td>
                        <td className="py-2.5 px-3 font-mono text-slate-200">
                          {item.total_amount !== null
                            ? `${item.currency ? `${item.currency} ` : ''}${item.total_amount}`
                            : 'N/A'}
                        </td>
                        <td className="py-2.5 px-3">
                          <span
                            className={`inline-block rounded border px-1.5 py-0.5 text-[10px] font-semibold ${getFieldStatusClasses(
                              item.extraction_status,
                            )}`}
                          >
                            {item.extraction_status}
                          </span>
                        </td>
                        <td className="py-2.5 px-3">
                          <span
                            className={`inline-block rounded border px-1.5 py-0.5 text-[10px] font-semibold ${itemMeta.classes}`}
                          >
                            {itemMeta.label}
                          </span>
                        </td>
                        <td className="py-2.5 pl-3 text-right font-semibold tabular-nums text-slate-200">
                          {item.findings_count}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>

      {/* Bottom: Selected / Latest Invoice Detail Inspection */}
      <section
        ref={detailsSectionRef}
        className="rounded-xl border border-slate-800 bg-[#0D1424] p-5"
      >
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-base font-semibold text-white">
              Invoice Investigation Details
            </h2>
            <p className="mt-0.5 text-xs text-slate-400">
              Extracted metadata, OCR status, and deterministic findings.
            </p>
          </div>
          {activeView && statusMeta && (
            <div className="flex flex-wrap items-center gap-2">
              {onAskAssistant && (
                <button
                  type="button"
                  onClick={() => onAskAssistant(activeView.invoice.id)}
                  className="rounded-md border border-sky-500/40 bg-sky-500/15 px-2.5 py-1 text-xs font-medium text-sky-300 transition hover:bg-sky-500/25"
                >
                  Ask AI about Invoice #{activeView.invoice.id}
                </button>
              )}
              <span
                className={`rounded-md border px-2.5 py-1 text-xs font-semibold ${statusMeta.classes}`}
              >
                {statusMeta.label}
              </span>
            </div>
          )}
        </div>

        {isDetailLoading ? (
          <div className="mt-4 rounded-lg border border-slate-800 bg-[#090E1A] p-6 text-center text-xs text-slate-400">
            Loading invoice investigation detail…
          </div>
        ) : detailError ? (
          <div
            role="alert"
            className="mt-4 rounded-lg border border-red-500/40 bg-red-500/10 p-4 text-xs text-red-200"
          >
            <p className="font-semibold text-red-100">Unable to load invoice details</p>
            <p className="mt-1">{detailError}</p>
          </div>
        ) : !activeView ? (
          <div className="mt-4 rounded-lg border border-slate-800 bg-[#090E1A] p-6 text-center text-xs text-slate-400">
            Select an invoice from History or upload a document to inspect extracted fields and findings.
          </div>
        ) : (
          <div className="mt-4 space-y-5">
            {/* Extraction & OCR Availability Status Banner */}
            <div className="rounded-lg border border-slate-800 bg-[#090E1A] p-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex flex-wrap items-center gap-2 text-xs">
                  <span className="font-semibold text-slate-100">
                    {activeView.invoice.original_filename}
                  </span>
                  <span className="text-slate-500">·</span>
                  <span className="text-slate-400">
                    {activeView.invoice.file_type} ({formatFileSize(activeView.invoice.file_size_bytes)}
                    {activeView.invoice.page_count !== null
                      ? `, ${activeView.invoice.page_count} page${activeView.invoice.page_count === 1 ? '' : 's'}`
                      : ''}
                    )
                  </span>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  <span
                    className={`rounded border px-2 py-0.5 text-[11px] font-semibold ${getFieldStatusClasses(
                      activeView.invoice.extraction_status,
                    )}`}
                  >
                    Extraction: {activeView.invoice.extraction_status}
                  </span>
                  <span
                    className={`rounded border px-2 py-0.5 text-[11px] font-semibold ${
                      activeView.invoice.ocr_available
                        ? 'border-emerald-500/35 bg-emerald-500/10 text-emerald-300'
                        : 'border-amber-500/35 bg-amber-500/10 text-amber-300'
                    }`}
                  >
                    {activeView.invoice.ocr_available
                      ? 'OCR Available'
                      : 'Tesseract OCR Unavailable'}
                  </span>
                </div>
              </div>

              {activeView.extractionNote && (
                <p className="mt-2 text-xs text-slate-300">{activeView.extractionNote}</p>
              )}

              {activeView.invoice.summary && (
                <p className="mt-2 border-t border-slate-800 pt-2 text-xs leading-relaxed text-slate-200">
                  {activeView.invoice.summary}
                </p>
              )}
            </div>

            {/* Extracted vs. User-Corrected Fields + Findings side by side */}
            <div className="grid grid-cols-1 gap-5 lg:grid-cols-12">
              <div className="lg:col-span-6 rounded-lg border border-slate-800 bg-[#121B2E]/70 p-4">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                  Extracted Invoice Fields
                </h3>
                <div className="mt-3 divide-y divide-slate-800/80 text-xs">
                  {activeView.fields.map((field) => (
                    <div
                      key={field.field_name}
                      className="flex flex-wrap items-start justify-between gap-2 py-2"
                    >
                      <div>
                        <span className="font-medium text-slate-300">
                          {FIELD_LABELS[field.field_name] ?? field.field_name}
                        </span>
                        <div className="mt-0.5 text-slate-100">
                          {field.extracted_value !== null ? (
                            <span className="font-mono">{field.extracted_value}</span>
                          ) : field.extraction_status === 'OCR_UNAVAILABLE' ? (
                            <span className="italic text-amber-300/90">
                              Unavailable (OCR needed)
                            </span>
                          ) : (
                            <span className="italic text-slate-500">Not extracted</span>
                          )}
                        </div>
                        {field.corrected_value !== null && (
                          <div className="mt-0.5 text-[11px] text-indigo-300">
                            User Correction:{' '}
                            <span className="font-mono font-semibold">
                              {field.corrected_value}
                            </span>
                          </div>
                        )}
                      </div>

                      <div className="flex items-center gap-1.5">
                        <span
                          className={`rounded border px-1.5 py-0.5 text-[10px] font-semibold ${getFieldStatusClasses(
                            field.extraction_status,
                          )}`}
                        >
                          {field.extraction_status}
                        </span>
                        {field.confidence !== 'NONE' && (
                          <span className="rounded border border-slate-700 bg-slate-800/80 px-1.5 py-0.5 text-[10px] text-slate-300">
                            {field.confidence}
                          </span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="lg:col-span-6 rounded-lg border border-slate-800 bg-[#121B2E]/70 p-4">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                  Deterministic Findings ({activeView.findings.length})
                </h3>

                {activeView.findings.length === 0 ? (
                  activeView.invoice.investigation_status === 'NO_FINDINGS' ? (
                    <div className="mt-3 rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-3 text-xs text-emerald-200">
                      No duplicate, arithmetic, date, or completeness findings were triggered on the extracted fields.
                    </div>
                  ) : (
                    <div className="mt-3 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-200">
                      Extraction was incomplete or unavailable; automated checks cannot confirm completeness.
                    </div>
                  )
                ) : (
                  <div className="mt-3 space-y-2.5">
                    {activeView.findings.map((finding, idx) => (
                      <div
                        key={finding.id ?? `${finding.finding_code}-${idx}`}
                        className="rounded-lg border border-slate-800 bg-[#0D1424] p-3 text-xs"
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-semibold text-slate-100">
                            {formatFindingCode(finding.finding_code)}
                          </span>
                          <span
                            className={`rounded border px-1.5 py-0.5 text-[10px] font-semibold ${getRiskBadgeClasses(
                              finding.severity,
                            )}`}
                          >
                            {finding.severity}
                          </span>
                        </div>
                        <p className="mt-1.5 leading-relaxed text-slate-300">
                          {finding.explanation}
                        </p>
                      </div>
                    ))}
                  </div>
                )}

                <p className="mt-4 border-t border-slate-800 pt-2 text-[11px] text-slate-500">
                  Deterministic invoice findings highlight billing discrepancies or extraction gaps for human review and do not declare confirmed fraud.
                </p>
              </div>
            </div>
          </div>
        )}
      </section>
    </div>
  )
}
