import { clsx } from "clsx"
import { twMerge } from "tailwind-merge"

/**
 * Merge conditional class names, with later Tailwind utilities winning over
 * earlier conflicting ones (so a `className` prop can override a component's
 * own defaults).
 */
export function cn(...inputs) {
  return twMerge(clsx(inputs))
}
