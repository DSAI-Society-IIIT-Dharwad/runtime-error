# 🐳 Docker Beginner's Guide for Home Net Guardian

## What is Docker?

Think of Docker as a **virtual shipping container** for your application. Just like shipping containers:
- They package everything needed (code, libraries, settings)
- They work the same way everywhere (your computer, my computer, a server)
- They're isolated from each other (one app can't mess up another)

## Key Concepts

### 🏗️ **Image**
- A blueprint/template for your application
- Like a recipe that describes how to build your app
- Example: `cyberproject-backend:latest`

### 📦 **Container**
- A running instance of an image
- Like a cake baked from a recipe
- You can have multiple containers from one image

### 🐙 **Docker Compose**
- A tool to run multiple containers together
- Defined in `compose.yaml` file
- Makes it easy to start/stop entire applications

## Your Home Net Guardian Setup

This project has **2 containers**:
1. **Backend** (Python/FastAPI) - The brain/API
2. **Frontend** (React/Vite) - The user interface

## Basic Commands You'll Use

### ✅ Starting the Application

```bash
# Build and start everything (first time or after changes)
docker-compose up --build

# Start in the background (detached mode)
docker-compose up -d

# Or just use the batch file!
LAUNCH.bat
```

### 🛑 Stopping the Application

```bash
# Stop containers (keeps them for next time)
docker-compose stop

# Stop and remove containers (clean slate)
docker-compose down

# Or use the batch file!
STOP.bat
```

### 👀 Viewing What's Running

```bash
# See all running containers
docker-compose ps

# Or see all Docker containers
docker ps
```

### 📜 Viewing Logs

```bash
# See logs from all containers
docker-compose logs

# Follow logs in real-time (like tail -f)
docker-compose logs -f

# See logs from just the backend
docker-compose logs backend

# See logs from just the frontend
docker-compose logs frontend
```

### 🔄 Restarting

```bash
# Restart all containers
docker-compose restart

# Restart just one service
docker-compose restart backend
```

### 🧹 Cleaning Up

```bash
# Remove stopped containers
docker-compose down

# Remove containers AND images (deep clean)
docker-compose down --rmi all

# Remove everything including volumes (nuclear option)
docker-compose down -v --rmi all
```

## Common Scenarios

### 🚀 First Time Setup
```bash
# 1. Make sure Docker Desktop is running
# 2. Open Command Prompt in project folder
# 3. Run:
docker-compose up --build

# Or just double-click LAUNCH.bat
```

### 🔧 After Making Code Changes
```bash
# Rebuild and restart
docker-compose up --build

# Or for specific service
docker-compose build backend
docker-compose up -d backend
```

### ❌ Something Went Wrong
```bash
# Stop everything
docker-compose down

# Clean rebuild
docker-compose build --no-cache
docker-compose up

# Check logs for errors
docker-compose logs
```

### 💾 Application Won't Start
```bash
# Check if containers are running
docker-compose ps

# Check for errors
docker-compose logs

# Try a clean start
docker-compose down
docker-compose up --build
```

## Understanding the Build Process

When you run `docker-compose up --build`:

1. **Downloads base images** (Python, Node.js) - only first time
2. **Installs dependencies** (pip packages, npm packages)
3. **Copies your code** into containers
4. **Starts the services**

The first build takes ~2-5 minutes. After that, it's much faster (30 seconds) because Docker caches layers.

## File Structure

```
Cyber Project/
├── compose.yaml          # Defines how containers work together
├── backend/
│   ├── Dockerfile       # Recipe for backend container
│   └── app.py           # Your backend code
├── frontend/
│   ├── Dockerfile       # Recipe for frontend container
│   └── src/             # Your frontend code
├── LAUNCH.bat           # Easy start button
└── STOP.bat             # Easy stop button
```

## Common Error Messages Explained

### ❌ "Cannot connect to Docker daemon"
**Meaning:** Docker Desktop isn't running
**Fix:** Start Docker Desktop application

### ❌ "port is already allocated"
**Meaning:** Another program is using ports 8000 or 5173
**Fix:** Stop the other program or change ports in `compose.yaml`

### ❌ "image already exists"
**Meaning:** Old image cached (this is actually fine!)
**Fix:** This usually resolves itself. If not: `docker-compose down --rmi all`

### ❌ "Error response from daemon"
**Meaning:** Docker service issue
**Fix:** Restart Docker Desktop

## Pro Tips 🎯

1. **Always check Docker Desktop is running** before commands
2. **Use `LAUNCH.bat`** for easiest experience
3. **Check logs** when something breaks: `docker-compose logs`
4. **Be patient** on first build (2-5 minutes is normal)
5. **Use `Ctrl+C`** to stop when running in foreground
6. **Use `-d` flag** to run in background: `docker-compose up -d`

## Ports in This Project

- **Frontend:** http://localhost:5173
- **Backend:** http://localhost:8000
- **API Docs:** http://localhost:8000/docs

## Quick Reference Card

| Task | Command |
|------|---------|
| Start | `docker-compose up` |
| Start (background) | `docker-compose up -d` |
| Stop | `docker-compose down` |
| View logs | `docker-compose logs -f` |
| Rebuild | `docker-compose build` |
| Status | `docker-compose ps` |
| Restart | `docker-compose restart` |

## Need Help?

1. **Check if Docker is running:** Look for Docker icon in system tray
2. **Check container status:** `docker-compose ps`
3. **Check logs:** `docker-compose logs`
4. **Try clean restart:** 
   ```bash
   docker-compose down
   docker-compose up --build
   ```

## What Happens When You Run LAUNCH.bat?

```
1. Stops any existing containers
2. Reads compose.yaml file
3. Builds backend image (Python + your code)
4. Builds frontend image (Node.js + your code)
5. Creates and starts containers
6. Shows you the logs
7. Application is accessible in browser
```

---

**Remember:** Docker makes it easy to run complex applications without installing everything manually. You just need Docker Desktop installed, and everything else happens automatically! 🚀

