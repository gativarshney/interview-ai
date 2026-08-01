import React from "react"
import { cn } from "@/lib/utils"

/**
 * The favicon mark, reused in-app so the tab icon and the header logo are the
 * same object rather than two unrelated drawings.
 */
export function LogoMark({ className }) {
  return (
    <svg viewBox="0 0 32 32" aria-hidden="true" className={cn("size-7 shrink-0", className)}>
      <rect width="32" height="32" rx="7" fill="currentColor" fillOpacity="0.06" />
      <rect
        x="0.5"
        y="0.5"
        width="31"
        height="31"
        rx="6.5"
        fill="none"
        stroke="currentColor"
        strokeOpacity="0.18"
      />
      <path
        d="M11 7h7.2L23 11.8V25a1 1 0 0 1-1 1H11a1 1 0 0 1-1-1V8a1 1 0 0 1 1-1Z"
        fill="currentColor"
        fillOpacity="0.14"
      />
      <path d="M18 7l5 4.8h-4a1 1 0 0 1-1-1V7Z" fill="currentColor" fillOpacity="0.32" />
      <g fill="currentColor">
        <rect x="13" y="19" width="2.6" height="3.6" rx="0.9" />
        <rect x="17" y="16.4" width="2.6" height="6.2" rx="0.9" />
      </g>
      <path
        d="M13.6 15.2l3-3 2.2 2.2 3.4-3.6"
        fill="none"
        stroke="var(--brand)"
        strokeWidth="2.1"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  )
}

export function Logo({ className, textClassName }) {
  return (
    <span className={cn("inline-flex items-center gap-2", className)}>
      <LogoMark />
      <span className={cn("text-[15px] font-semibold tracking-[-0.02em]", textClassName)}>
        Interview Copilot
      </span>
    </span>
  )
}

export default Logo
