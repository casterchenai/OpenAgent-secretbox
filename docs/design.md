# SecretBox interface standard

## Product and audience

SecretBox is an operational security surface for people working through an AI
agent UI. The user reviews a request and supplies values; they do not browse the
server filesystem or learn SecretBox commands.

## Visual direction

Use a quiet technical interface with strong trust cues. Keep the canvas white,
text near-black, supporting surfaces neutral, and one emerald primary action.
Do not use gradients, decorative illustrations, oversized headings, nested
cards, or marketing composition inside the intake flow.

## Tokens

- Canvas: `#ffffff`; secondary canvas: `#f7f8f7`.
- Text: `#171917`; muted text: `#667068`.
- Border: `#d9dedb`; strong border: `#aeb7b1`.
- Primary: `#238636`; primary hover: `#1a6f2b`.
- Warning surface: `#fff8dc`; warning text: `#684f00`.
- Error surface: `#fff1f0`; error text: `#9b1c1c`.
- Radius: 6px controls, 8px bounded request items and notices.
- Spacing rhythm: 4, 8, 12, 16, 24, 32px.
- Typography: system sans; system monospace for paths and variable names.
  Letter spacing is always `0`.

## Layout

Constrain forms to 760px. Keep request identity, workspace context, target list,
and the primary action visible in a single vertical reading order. At mobile
widths, stack metadata and actions without horizontal scrolling.

## Components and states

- Use native inputs and file controls with persistent labels.
- Use one filled primary button for submit or login.
- Use outline or text buttons for cancel and sign out.
- Show paths and variable names in monospace, with wrapping rather than clipping.
- Display pending, applied, conflict, expired, cancelled, invalid-link, and
  authentication-error states explicitly.
- Never display submitted values, file previews, hashes, or encoded derivatives.
- Do not place a card inside another card. Request items may use one bounded row.

## Accessibility and responsive rules

- Maintain visible focus states and native keyboard order.
- Keep controls at least 40px high and touch targets at least 44px on mobile.
- Associate every input with a label and every notice with an appropriate live
  region or alert role.
- Do not use color as the only status signal.
- Verify at 320px, 390px, 768px, and a desktop viewport.

## Agent discipline

Before UI work, read this standard. Preserve its tokens, spacing rhythm,
interaction states, responsive behavior, and secret-display prohibitions.
Update this document when intentionally changing the visual direction; do not
introduce a parallel visual system.

## QA checklist

- No secret, bearer, or uploaded content is rendered after submission.
- Long paths and labels do not overlap controls.
- Login, pending, success, conflict, expired, cancelled, and invalid states are
  visually distinct and understandable without technical knowledge.
- Desktop and mobile layouts remain stable as status text changes.
