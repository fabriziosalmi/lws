# LWS Documentation

This directory contains the complete documentation for LWS, hosted on GitHub Pages.

## 🌐 View Documentation

**Live site:** [https://fabriziosalmi.github.io/lws/](https://fabriziosalmi.github.io/lws/)

## 📁 Structure

```
docs/
├── index.html              # Landing page
├── _config.yml            # Jekyll configuration
├── .nojekyll              # Disable default Jekyll processing
├── CNAME                  # Custom domain (optional)
│
├── assets/
│   ├── css/
│   │   └── style.css      # Custom styles
│   ├── js/
│   │   └── main.js        # JavaScript for animations
│   └── img/
│       └── (images)
│
└── pages/
    ├── getting-started.md
    ├── architecture.md
    ├── cli-reference.md
    ├── api-reference.md
    ├── configuration.md
    └── contributing.md
```

## 🚀 Enabling GitHub Pages

### Step 1: Push to GitHub

```bash
git add docs/
git commit -m "Add comprehensive documentation with GitHub Pages"
git push origin main
```

### Step 2: Enable GitHub Pages

1. Go to your repository on GitHub
2. Click **Settings**
3. Scroll to **Pages** section (left sidebar)
4. Under **Source**, select:
   - **Branch:** `main`
   - **Folder:** `/docs`
5. Click **Save**

### Step 3: Wait for Deployment

GitHub Pages will build and deploy your site. This usually takes 1-3 minutes.

You can check the deployment status under:
- **Actions** tab → **pages-build-deployment** workflow

### Step 4: Access Your Site

Your documentation will be available at:
```
https://YOUR_USERNAME.github.io/lws/
```

For example:
```
https://fabriziosalmi.github.io/lws/
```

## 🎨 Customization

### Change Colors

Edit `docs/assets/css/style.css`:

```css
:root {
    --primary: #6366f1;      /* Change primary color */
    --secondary: #ec4899;     /* Change secondary color */
    --accent: #14b8a6;        /* Change accent color */
}
```

### Add Custom Domain

1. Create/edit `docs/CNAME`:
   ```
   docs.yourdomain.com
   ```

2. Configure DNS:
   - Add CNAME record pointing to `YOUR_USERNAME.github.io`

3. Enable HTTPS in GitHub Pages settings

### Update Content

All documentation is in Markdown format in `docs/pages/`:
- `getting-started.md` - Installation guide
- `architecture.md` - Technical architecture
- `cli-reference.md` - CLI commands
- `api-reference.md` - API endpoints
- `configuration.md` - Configuration options
- `contributing.md` - Contributing guide

Simply edit these files and push to update the documentation.

## 🧪 Local Development

### Preview Locally

You can preview the documentation locally using Python's built-in server:

```bash
cd docs
python3 -m http.server 8000
```

Then open: `http://localhost:8000`

### With Jekyll (Optional)

If you want to preview with Jekyll:

```bash
# Install Jekyll
gem install bundler jekyll

# Create Gemfile in docs/
cd docs
cat > Gemfile << 'EOF'
source "https://rubygems.org"
gem "github-pages", group: :jekyll_plugins
EOF

# Install dependencies
bundle install

# Serve locally
bundle exec jekyll serve

# Open http://localhost:4000
```

## 📝 Maintenance

### Update Navigation

Edit `docs/_config.yml` to update the navigation menu:

```yaml
navigation:
  - title: Getting Started
    url: /pages/getting-started
  - title: New Page
    url: /pages/new-page
```

### Add New Pages

1. Create new Markdown file in `docs/pages/`
2. Add front matter:
   ```yaml
   ---
   layout: default
   title: Page Title
   ---
   ```
3. Write content in Markdown
4. Add link to navigation in `_config.yml`
5. Update `index.html` if needed

## 🐛 Troubleshooting

### Page Not Found (404)

- Check that GitHub Pages is enabled
- Verify the branch and folder are correct
- Wait a few minutes for deployment
- Check the Actions tab for build errors

### CSS Not Loading

- Verify file paths in `index.html`
- Check browser console for errors
- Ensure `assets/` directory is committed

### Markdown Not Rendering

- Check front matter in `.md` files
- Verify `_config.yml` is valid YAML
- Ensure Jekyll theme is properly configured

## 📚 Resources

- [GitHub Pages Documentation](https://docs.github.com/en/pages)
- [Jekyll Documentation](https://jekyllrb.com/docs/)
- [Markdown Guide](https://www.markdownguide.org/)

## ✅ Checklist

- [ ] Push `docs/` to GitHub
- [ ] Enable GitHub Pages in settings
- [ ] Wait for deployment
- [ ] Verify site is accessible
- [ ] Update README.md with documentation link
- [ ] (Optional) Configure custom domain
- [ ] (Optional) Enable HTTPS

---

**Questions or issues?** Open an issue on GitHub!
