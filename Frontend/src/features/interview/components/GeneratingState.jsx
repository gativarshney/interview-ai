import React, { useEffect, useState } from 'react'
import { Loader2 } from 'lucide-react'

const TYPICAL_SECONDS = 30

/**
 * Shown only while a report is genuinely being generated — the one operation
 * here that really does take ~30s.
 *
 * Deliberately does not invent progress. The server returns one response at the
 * end, so the only honest signals are "still working" and how long it has been.
 * The previous screen cycled through eight fabricated stage messages on a timer,
 * which implied progress it could not know.
 */
const GeneratingState = () => {
    const [elapsed, setElapsed] = useState(0)

    useEffect(() => {
        const id = setInterval(() => setElapsed((s) => s + 1), 1000)
        return () => clearInterval(id)
    }, [])

    const overrun = elapsed > TYPICAL_SECONDS + 15
    const pct = Math.min((elapsed / TYPICAL_SECONDS) * 100, 96)

    return (
        <div
            className="flex min-h-[60vh] w-full items-center justify-center px-6"
            role="status"
            aria-live="polite"
        >
            <div className="w-full max-w-md rounded-lg border border-border bg-card p-8">
                <div className="flex items-center gap-3">
                    <Loader2 className="size-4 animate-spin text-muted-foreground" aria-hidden="true" />
                    <h2 className="text-[15px] font-semibold tracking-[-0.02em]">
                        Reading your resume against the role
                    </h2>
                </div>

                <p className="mt-3 text-sm leading-relaxed text-muted-foreground">
                    {overrun
                        ? "Taking longer than usual. The model is still working — this can happen with long job descriptions."
                        : "This usually takes about 30 seconds. You will get questions, skill gaps and a prep plan when it finishes."}
                </p>

                {/* Elapsed time, not a simulated stage counter. */}
                <div className="mt-6 h-px w-full overflow-hidden bg-border">
                    <div
                        className="h-px bg-foreground/40 transition-[width] duration-1000 ease-linear"
                        style={{ width: `${pct}%` }}
                    />
                </div>

                <div className="mt-3 flex items-center justify-between text-xs text-muted-foreground">
                    <span className="font-mono tabular-nums">
                        {String(Math.floor(elapsed / 60)).padStart(2, '0')}:
                        {String(elapsed % 60).padStart(2, '0')} elapsed
                    </span>
                    <span>Don't close this tab</span>
                </div>
            </div>
        </div>
    )
}

export default GeneratingState
