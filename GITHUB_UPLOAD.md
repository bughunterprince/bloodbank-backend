# Upload Backend to GitHub (Without Git CLI)

## Method 1: Using GitHub Web Interface

1. **Create New Repository**
   - Go to https://github.com
   - Click "New Repository"
   - Name: `bloodbank-backend`
   - Make it **Public**
   - Don't check "Add README"

2. **Upload Files**
   - Click "uploading an existing file"
   - Drag and drop ALL files from this backend folder:
     - app.py
     - requirements.txt
     - Procfile
     - render.yaml
     - README.md
     - .gitignore
     - bloodbank.db
     - .env
     - env

3. **Commit**
   - Add commit message: "Initial backend commit"
   - Click "Commit new files"

## Method 2: Using Git (Recommended)

```bash
# Install Git first from: https://git-scm.com/download/win
git init
git add .
git commit -m "Initial backend commit"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/bloodbank-backend.git
git push -u origin main
```

## Deploy on Render

1. Go to https://render.com
2. Click "New Web Service"
3. Connect your GitHub repository
4. Configuration:
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `python app.py`
   - **Environment Variables**:
     - `DB_ENGINE=sqlite`
     - `SECRET_KEY=your-secret-key`
     - `OTP_MODE=console`

Your backend will be live at: `https://your-app-name.onrender.com`