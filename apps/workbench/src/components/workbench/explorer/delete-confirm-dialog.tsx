import type { ProjectFile } from "@/features/project/stores/project-store";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

interface DeleteConfirmDialogProps {
  file: ProjectFile | null;
  open: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

export function DeleteConfirmDialog({
  file,
  open,
  onConfirm,
  onCancel,
}: DeleteConfirmDialogProps) {
  return (
    <Dialog open={open} onOpenChange={(isOpen) => { if (!isOpen) onCancel(); }}>
      <DialogContent
        className="bg-[#131721] border border-[#2d3240] text-[#ece7dc]"
        showCloseButton={false}
      >
        <DialogHeader>
          <DialogTitle className="text-[13px] font-mono text-[#ece7dc]">
            Delete File
          </DialogTitle>
          <DialogDescription className="text-[11px] font-mono text-[#6f7f9a]">
            Are you sure you want to delete &quot;{file?.name}&quot;? This cannot be undone.
          </DialogDescription>
        </DialogHeader>
        <DialogFooter className="bg-transparent border-t-0">
          <button
            type="button"
            onClick={onCancel}
            className="px-3 py-1.5 text-[11px] font-mono rounded border border-[#2d3240] text-[#ece7dc] hover:bg-[#2d3240]/50 transition-colors"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={onConfirm}
            className="px-3 py-1.5 text-[11px] font-mono rounded bg-red-600 hover:bg-red-700 text-white transition-colors"
          >
            Delete
          </button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
