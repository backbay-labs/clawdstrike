/**
 * TUI Components - Pure functional rendering components.
 *
 * Each component is a pure function that takes state, dimensions, and theme
 * configuration, and returns string[] (rendered lines).
 */

export type { ThemeColors } from "./types"
export { stripAnsi, visibleLength, fitString, truncateAnsi } from "./types"

export type { BoxOptions } from "./box"
export { renderBox } from "./box"

export type { ListItem, ListViewport } from "./scrollable-list"
export { renderList, scrollUp, scrollDown } from "./scrollable-list"

export type { TreeNode, TreeViewport } from "./tree-view"
export {
  renderTree,
  flattenTree,
  toggleExpand,
  moveUp as treeMoveUp,
  moveDown as treeMoveDown,
} from "./tree-view"

export type {
  FormFieldType,
  TextField,
  SelectField,
  ToggleField,
  FormField,
  FormState,
} from "./form"
export { renderForm, focusNext, focusPrev, handleFieldInput } from "./form"

export type { GridCell, GridSelection } from "./grid"
export { renderGrid, moveSelection } from "./grid"

export type { LogLine, LogState } from "./streaming-log"
export {
  renderLog,
  appendLine,
  togglePause,
  scrollLogUp,
  scrollLogDown,
  clearLog,
  createLogState,
} from "./streaming-log"

export { renderSplit } from "./split-pane"

export type { StatusBarData } from "./status-bar"
export { renderStatusBar } from "./status-bar"
