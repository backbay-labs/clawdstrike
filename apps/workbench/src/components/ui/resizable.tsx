import * as React from "react"
import { Panel, PanelGroup, PanelResizeHandle } from "react-resizable-panels"
import type { ImperativePanelGroupHandle, PanelGroupProps, PanelProps, PanelResizeHandleProps } from "react-resizable-panels"

import { cn } from "@/lib/utils"

function ResizablePanelGroup({
  className,
  ...props
}: PanelGroupProps & { ref?: React.Ref<ImperativePanelGroupHandle> }) {
  return (
    <PanelGroup
      data-slot="resizable-panel-group"
      className={cn(
        "flex h-full w-full data-[panel-group-direction=vertical]:flex-col",
        className
      )}
      {...props}
    />
  )
}

function ResizablePanel({ ...props }: PanelProps) {
  return <Panel data-slot="resizable-panel" {...props} />
}

function ResizableHandle({
  withHandle,
  className,
  ...props
}: PanelResizeHandleProps & {
  withHandle?: boolean
}) {
  return (
    <PanelResizeHandle
      data-slot="resizable-handle"
      className={cn(
        "relative flex w-px items-center justify-center bg-[#2d3240] after:absolute after:inset-y-0 after:left-1/2 after:w-1 after:-translate-x-1/2 focus-visible:ring-1 focus-visible:ring-[#d4a84b] focus-visible:outline-hidden data-[panel-group-direction=vertical]:h-px data-[panel-group-direction=vertical]:w-full data-[panel-group-direction=vertical]:after:left-0 data-[panel-group-direction=vertical]:after:h-1 data-[panel-group-direction=vertical]:after:w-full data-[panel-group-direction=vertical]:after:translate-x-0 data-[panel-group-direction=vertical]:after:-translate-y-1/2",
        className
      )}
      {...props}
    >
      {withHandle && (
        <div className="z-10 flex h-6 w-1 shrink-0 rounded-lg bg-[#2d3240]" />
      )}
    </PanelResizeHandle>
  )
}

export { ResizableHandle, ResizablePanel, ResizablePanelGroup }
