import React from "react"
import { cn } from "@/lib/utils"

/**
 * Placeholder block shown while real content loads. Sized by the caller so the
 * skeleton matches the shape of what replaces it and the layout does not jump.
 */
export function Skeleton({ className, ...props }) {
  return (
    <div
      className={cn("animate-pulse rounded-md bg-foreground/[0.07]", className)}
      {...props}
    />
  )
}

export default Skeleton
