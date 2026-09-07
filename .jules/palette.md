## 2024-05-19 - Init Command UX Improvement
**Learning:** CLI outputs with inline repetitive warnings (e.g. `already contains rules — skipping`) can clutter terminal visibility and diminish developer experience.
**Action:** Group skipped/unchanged files separately from modified ones (e.g., in a single `Skipped (already configured):` section) to create clean, scannable terminal output.

## 2024-07-12 - Native Dialog Backdrop Pattern
**Learning:** The native `<dialog>` element provides a built-in way to detect backdrop clicks without extra backdrop wrappers or complex z-index management. Clicking the backdrop fires a click event where `e.target` is the dialog element itself, whereas clicking the modal content sets `e.target` to a child element.
**Action:** When using `<dialog>`, implement backdrop click-to-close with a simple `if (e.target === dialog) dialog.close()` listener to improve modal UX with zero dependencies.

## 2024-08-05 - Dynamic Rendering Cursor Position
**Learning:** When recreating input elements dynamically during client-side rendering (e.g. updating `innerHTML` after a search keystroke), re-focusing the element isn't enough. Simply placing the cursor at the end of the value disrupts users who are editing text in the middle of a string.
**Action:** Always capture `e.target.selectionStart` and `e.target.selectionEnd` before the DOM is replaced, and use `el.setSelectionRange(start, end)` after the element is re-rendered to maintain a seamless typing experience.

## 2025-02-18 - Making interactive non-button elements accessible
**Learning:** When adding interactive behavior (e.g. `onclick`) to non-interactive HTML elements like `<tr>` in frameworkless HTML files, screen readers and keyboard navigation users are entirely blocked unless explicitly handled.
**Action:** Always ensure keyboard accessibility by adding `tabindex="0"`, `role="button"`, an appropriate `aria-label`, focus styles (`:focus-visible`), and a `keydown` listener to handle `Enter` and `Space` key presses.

## 2024-10-24 - Interactive Table Rows Keyboard Accessibility
**Learning:** Interactive table rows (e.g. `tr.scan` with `onclick` handlers) are not inherently accessible to keyboard users. Screen readers may ignore them, and they cannot be focused or activated via keyboard.
**Action:** When making table rows interactive, always add `tabindex="0"`, `role="button"`, an appropriate `aria-label`, and a `keydown` event listener to handle `Enter` and `Space` key presses.

## 2026-07-18 - 표준화된 에러 메시지와 동적 복수형 처리
**Learning:** CLI 도구에서 에러 메시지의 일관성(`❌ Error:`)과 실천 가능한 조언(`💡 Hint:`)의 명확한 구분은 사용자의 문제 해결 경험을 크게 향상시킨다. 또한 하드코딩된 복수형 접미사(예: `components`)는 터미널 출력의 품질을 떨어뜨린다.
**Action:** 향후 CLI 출력 메시지를 작성할 때, 반드시 일관된 접두어를 사용하고, 수량에 따른 단수/복수 처리를 삼항 연산자 등을 통해 동적으로 처리해야 한다.

## 2024-07-08 - Conditionally disable CLI emojis
**Learning:** Heavy emoji usage in CLI tools can degrade accessibility for screen readers and cause issues in non-UTF8 terminals or log parsers.
**Action:** Implement a targeted regex filter toggled by `APPGUARDRAIL_NO_EMOJI` to gracefully degrade CLI output without stripping valid international text.

## 2024-07-28 - Accessibility improvements for tables and native dialogs
**Learning:** For screen readers, tables need explicit associations, and controls opening modals should indicate dialog behavior.
**Action:** Use `aria-haspopup="dialog"` on interactive rows, `scope="col"` on headers, and `aria-labelledby` with a concrete title id for `<dialog>`.

## 2026-07-28 - Native HTML dialog focus restoration
**Learning:** Native `<dialog>` does not automatically restore focus to the trigger element on close, breaking keyboard navigation flow.
**Action:** Save `document.activeElement` before `showModal()` and restore focus to it in a `close` event listener.

## 2026-07-30 - Async Loading States Accessibility
**Learning:** Adding visual loading states without explicit ARIA declarations leaves screen reader users unaware of background network requests.
**Action:** Always declare the loading state explicitly by setting `aria-busy="true"` on the trigger element, and wrap dynamic status or error updates in containers with `aria-live="polite"` or `role="alert"`.

## 2024-05-24 - Do not use aria-label on table rows
**Learning:** Setting `aria-label` on table rows (`<tr>`), even those with `role="button"`, overrides natural table cell reading and hides critical table data from screen reader users.
**Action:** Use the `title` attribute instead to preserve natural cell reading while providing visual tooltip feedback for mouse users.

## 2024-11-20 - Empty State Clear Filters CTA
**Learning:** Users can get stuck when filtering a dashboard to zero results, and forcing them to manually clear multiple inputs creates friction.
**Action:** Add an interactive 'Clear filters' Call-To-Action within empty state messages to instantly reset state and refocus the primary input.

## 2026-08-03 - Focus Restoration and Stable Live Regions
**Learning:** Full-DOM replacement removes active controls and any live region nested inside the replaced subtree. Restoring only focus is insufficient for editable fields because their selection range is also lost.
**Action:** Capture the active element id and text selection bounds before rendering, restore both afterward, and publish updates through a persistent `aria-live="polite"` and `aria-atomic="true"` region by changing only its `textContent`.

## 2026-08-03 - Global Keyboard Shortcuts Interference
**Learning:** Adding a global keyboard shortcut (like `/` for search) without checking the currently focused element disrupts user text input. If a user tries to type the shortcut character into any standard input, textarea, or select element, the keydown event is hijacked.
**Action:** When implementing global keyboard shortcuts, always check `document.activeElement.tagName` and ignore the shortcut if the user is currently focused on an interactive text element (`input`, `textarea`, `select`).

## 2026-08-04 - Native File Input Iteration Friction
**Learning:** Browsers suppress `change` events when a file input still holds the same selected path. Clearing the value in an inline `onclick` handler fixes repetition but also discards the previous selection when the user cancels the picker and couples behavior to markup.
**Action:** Capture the selected `File` in the input's `change` listener, clear the input value immediately afterward, and then process the captured object. Use native buttons with explicit event listeners to proxy the picker from an empty-state CTA, preserving keyboard access and CSP-compatible separation of markup and behavior.

## 2026-08-06 - Dashboard status semantics
**Learning:** A loaded report with zero findings is a successful security outcome, not the same state as missing input. Announcing the same update through multiple live regions can also create duplicate screen-reader output.
**Action:** Keep one pre-existing polite, atomic status region; separate unloaded and clean-report states with an explicit loaded sentinel; and centralize English finding-count grammar in one formatter.

## 2025-02-18 - Search Input Escape Key
**Learning:** Users who heavily rely on keyboard navigation (and power users) experience friction when forced to backspace manually or switch to the mouse to click a "Clear" button after filtering a list.
**Action:** Always provide an `Escape` key listener on search inputs to instantly clear the query and re-render the view, matching native OS text field behavior.

## 2026-08-10 - Keyboard Accessible CSS Charts
**Learning:** DOM-based CSS charts (like bar graphs using styled `<div>` elements) are inherently inaccessible to keyboard and screen reader users unless explicitly configured. Without focus management and roles, interactive or informative charts become invisible to assistive technologies.
**Action:** Always add `tabindex="0"`, `role="img"`, an explicit `aria-label`, and a `:focus-visible` outline to individual chart elements so keyboard users can navigate them and screen readers can announce their data points.

## 2026-08-06 - Interactive Dashboard Cards for Quick Filtering
**Learning:** Making metric cards (like severity counts) interactive significantly reduces friction compared to using dropdown filters. It's a common dashboard pattern that users intuitively try to click, and explicitly adding `role="button"`, `tabindex="0"`, and `aria-pressed` makes it accessible.
**Action:** When aggregate metric cards act as filter toggles, give them an accessible name that includes the current count, expose `role="button"`, `tabindex="0"`, and `aria-pressed`, and handle both `Enter` and `Space` activation while preventing the Space key's default scrolling.

## 2026-08-12 - Async Detail Focus Restoration
**Learning:** Closing an asynchronous detail panel without invalidating the pending request lets a late response repopulate the panel or steal focus after the user has left it.
**Action:** Invalidate the request generation on close, restore focus only to a connected trigger, and expose equivalent Escape and close-button paths for success and error states.

## 2026-08-12 - Skip to Content Accessibility
**Learning:** Screen reader and keyboard-only users experience significant friction when forced to navigate through repetitive header controls on every page load.
**Action:** Keep a visible-on-focus skip link as the first interactive element, target a programmatically focusable main container, and give the focused link a high-contrast outline.

## 2026-08-14 - Playwright File Protocol Network Interception
**Learning:** When using Playwright to visually verify static HTML files loaded via `file://` URIs, `page.route()` may fail to intercept `fetch` requests effectively due to Chromium's security policies and handling of the file protocol.
**Action:** Mock the API by using `page.add_init_script()` to directly override `window.fetch` or inject mock data into the client-side context via `page.evaluate()` rather than relying on `page.route()`.

## 2026-08-14 - Pointer-events and Cursor CSS Interactions
**Learning:** Setting `pointer-events: none` on an element completely disables mouse interactions, which means a concurrent `cursor: not-allowed` rule on the same element will never be triggered. The element will fall back to its parent's cursor.
**Action:** While `pointer-events: none` is useful for preventing clicks, recognize that it prevents custom cursors. For native elements like `<button disabled>`, rely on the `disabled` attribute along with `cursor: not-allowed` and visual fading. For non-native elements, use Javascript guards instead of `pointer-events: none` if a custom cursor is strictly required, or accept the parent's cursor.
