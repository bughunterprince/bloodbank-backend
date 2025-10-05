@echo off
echo Instructions to upload Backend to GitHub:
echo.
echo 1. Go to https://github.com and create a new repository
echo    - Repository name: bloodbank-backend
echo    - Make it Public
echo    - Don't initialize with README (we already have one)
echo.
echo 2. Download and install Git from: https://git-scm.com/download/win
echo.
echo 3. After installing Git, open Command Prompt in this backend folder and run:
echo    git init
echo    git add .
echo    git commit -m "Initial backend commit"
echo    git branch -M main
echo    git remote add origin https://github.com/YOUR_USERNAME/bloodbank-backend.git
echo    git push -u origin main
echo.
echo 4. Then go to Render.com and deploy from your GitHub repository
echo.
echo Files ready for deployment:
dir /b
echo.
pause