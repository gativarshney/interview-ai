import React from 'react'
import { Skeleton } from '@/components/ui/skeleton'

/**
 * Placeholder for fetching an existing report. This is a fast GET, so it gets a
 * skeleton in the shape of the real page rather than the generation screen the
 * page used to show for every load.
 */
const ReportSkeleton = () => (
    <div className="mx-auto w-full max-w-6xl px-6 py-10" aria-hidden="true">
        <Skeleton className="h-4 w-28" />

        <div className="mt-8 grid gap-10 lg:grid-cols-[220px_1fr_260px]">
            <div className="hidden flex-col gap-3 lg:flex">
                <Skeleton className="h-3 w-16" />
                {[0, 1, 2].map((i) => (
                    <Skeleton key={i} className="h-9 w-full" />
                ))}
            </div>

            <div className="flex flex-col gap-4">
                <Skeleton className="h-7 w-56" />
                {[0, 1, 2, 3].map((i) => (
                    <Skeleton key={i} className="h-16 w-full" />
                ))}
            </div>

            <div className="hidden flex-col gap-4 lg:flex">
                <Skeleton className="size-28 self-center rounded-full" />
                <Skeleton className="h-3 w-24" />
                <div className="flex flex-wrap gap-2">
                    {[0, 1, 2, 3].map((i) => (
                        <Skeleton key={i} className="h-6 w-20 rounded-full" />
                    ))}
                </div>
            </div>
        </div>
    </div>
)

export default ReportSkeleton
