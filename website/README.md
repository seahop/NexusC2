# NexusC2 Website

Static documentation website for NexusC2, built with Hugo.

## Tech Stack

- **Hugo** - Static site generator
- **Tailwind CSS** - Styling
- **Mermaid.js** - Architecture diagrams
- **Pagefind** - Client-side search

## Development

### Prerequisites

- Node.js 18+
- Hugo Extended (0.111+)

### Local Development

```bash
# Install dependencies
npm install

# Build CSS (watches for changes)
npm run dev

# Run Hugo server (in another terminal)
hugo server -D
```

### Building for Production

```bash
# Build CSS
npm run build

# Build Hugo site
hugo --minify

# Generate search index
npx pagefind --source public
```

## Directory Structure

```
website/
├── assets/css/          # Tailwind source CSS
├── config.toml          # Hugo configuration
├── content/             # Website content (markdown)
│   ├── _index.md        # Homepage
│   ├── features/        # Features page
│   ├── docs/            # Documentation
│   ├── commands/        # Command reference
│   └── howto/           # How-to guides
├── data/                # Generated data files
│   └── commands.json    # Parsed from commands.toml
├── layouts/             # Hugo templates
├── static/              # Static assets (images, fonts)
└── tailwind.config.js
```
