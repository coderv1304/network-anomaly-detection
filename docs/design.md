# NetShield AI — Design System Specification

## 1. Vision & Aesthetics
The NetShield AI design system blends **deep roast espresso**, **warm light coffee brown / caramel**, **brushed platinum silver**, and a subtle **ethereal light warm lavender accent**. 

This aesthetic elevates the platform from an off-the-shelf security console into a bespoke, editorial cybersecurity intelligence interface.

---

## 2. Color Palette & Swatches

### Dark Mode (Primary Theme — Deep Espresso & Platinum)
| Token Name | Hex Code | Visual Sample / Swatch | Role & Usage |
| :--- | :--- | :--- | :--- |
| `--bg` | `#110e0c` | `■` Deep Espresso | Core background for main window |
| `--surface` | `#221a17` | `■` Roasted Coffee | Card panels, topbar, modal backgrounds |
| `--surface-raised`| `#2a211d` | `■` Warm Slate | Raised elements, input backgrounds |
| `--line` | `#3d322d` | `■` Muted Umber | Subtle dividers and card borders |
| `--silver` | `#d1d5db` | `■` Brushed Silver | Headers, secondary text, border rings |
| `--silver-bright`| `#f3f4f6` | `■` Platinum White | Highest contrast labels & active icons |
| `--coffee-base` | `#6f4e37` | `■` Rich Coffee Brown | Primary action buttons (`.btn-primary`) |
| `--coffee-caramel`| `#c49a6c` | `■` Warm Caramel | Accent text, hero gradient, brand badges |
| `--lavender` | `#d7c7f4` | `■` Warm Lavender | Glow effects, focus rings, hover aura |
| `--green` | `#48bb78` | `■` Emerald Sage | Benign network flow status |
| `--red` | `#f56565` | `■` Crimson Coral | Critical intrusion alerts |

### Light Mode (Café Crème & Silver)
| Token Name | Hex Code | Visual Sample | Role & Usage |
| :--- | :--- | :--- | :--- |
| `--bg` | `#f9f6f2` | `■` Café Crème | Light body background |
| `--surface` | `#ffffff` | `■` Pure Ivory | Main card surfaces |
| `--coffee-base` | `#5a3c28` | `■` Roast Mocha | Primary buttons and brand elements |
| `--lavender` | `#6d549a` | `■` Deep Lavender | Interactive focus states & highlights |

---

## 3. Typography Pairings

- **Display Headings**: `Playfair Display` (Serif, 500/600/700)
  - Used for: Brand typography (`NETSHIELD AI`), Hero Title (`Network Traffic Anomaly Detection`), Card section headers, metric counters.
- **Body & Controls**: `Inter` (Sans-serif, 300/400/500/600/700)
  - Used for: Paragraphs, data table cells, tooltips, buttons.
- **Code & Telemetry**: `JetBrains Mono` (Monospace, 400/500/600)
  - Used for: IP addresses, ports, timestamps, hex packet payloads.

---

## 4. Component Standards

### Cards (`.card`, `.card-glow`)
```html
<div class="card card-glow">
  <div class="action-header">
    <h2>Threat Intelligence Stream</h2>
  </div>
  <p>Real-time packet inspection details.</p>
</div>
```

### Primary Buttons (`.btn-primary`)
```html
<button class="btn-primary">
  Execute Model Inference
</button>
```

### Form Inputs (`.input`)
```html
<input type="text" class="input" placeholder="Filter by IP address (e.g., 192.168.1.1)">
```

### Drag & Drop Ingestion Zone (`.upload-zone`)
- Highlighted with a dashed platinum silver line.
- Features a warm lavender aura (`rgba(215, 199, 244, 0.22)`) on hover and file drag-over.

---

## 5. Accessibility & Contrast (WCAG 2.1 AA)
- High contrast ratio on dark backgrounds: Text (`#fdfaf7`) over background (`#110e0c`) yields a **17.8:1** contrast ratio (far exceeding the 4.5:1 AA standard).
- Buttons feature high-contrast silver borders and explicit focus rings (`var(--lavender-glow)`).
