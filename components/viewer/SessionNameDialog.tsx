"use client";

import { useState } from "react";

import type { Dict } from "@/src/dict/types";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";

/** Name a session on first save, or rename it later. */
export function SessionNameDialog({
  open,
  onOpenChange,
  dict,
  title,
  description,
  initialName,
  confirmLabel,
  onConfirm,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  dict: Dict;
  title: string;
  description?: string;
  initialName: string;
  confirmLabel: string;
  onConfirm: (name: string) => void;
}) {
  const v = dict.viewer;
  // Reset the field to the suggested name each time the dialog opens.
  const [state, setState] = useState({ open, name: initialName });
  let name = state.name;
  if (state.open !== open) {
    name = open ? initialName : state.name;
    setState({ open, name });
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <form
          className="grid gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            if (!name.trim()) return;
            onConfirm(name.trim());
            onOpenChange(false);
          }}
        >
          <DialogHeader>
            <DialogTitle>{title}</DialogTitle>
            {description && <DialogDescription>{description}</DialogDescription>}
          </DialogHeader>
          <label className="grid gap-1.5 text-sm">
            <span className="font-medium">{v.sessionName}</span>
            <Input
              autoFocus
              value={name}
              maxLength={120}
              onChange={(e) => setState((s) => ({ ...s, name: e.target.value }))}
              onFocus={(e) => e.currentTarget.select()}
            />
          </label>
          <DialogFooter>
            <DialogClose render={<Button type="button" variant="outline" />}>
              {v.cancel}
            </DialogClose>
            <Button type="submit" disabled={!name.trim()}>
              {confirmLabel}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
