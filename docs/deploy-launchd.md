# Deploying with launchd (macOS)

`deploy/com.holdmyagent.arbiter.plist` runs Arbiter as a per-user launch
agent that starts at login and restarts if it crashes.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.holdmyagent.arbiter</string>
  <key>ProgramArguments</key><array>
    <string>/usr/local/bin/hma</string><string>serve</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/tmp/holdmyagent.log</string>
  <key>StandardErrorPath</key><string>/tmp/holdmyagent.err</string>
</dict></plist>
```

## Setup

1. Install Arbiter and find where `hma` actually landed — launchd doesn't
   read your shell's `PATH`, so the plist needs an absolute path, and
   that path depends on how you installed it (Homebrew Python vs. Apple
   Silicon Homebrew vs. `pipx` vs. a plain user install all differ):

   ```bash
   pip install --user holdmyagent
   which hma
   # e.g. /Users/you/Library/Python/3.12/bin/hma, or /opt/homebrew/bin/hma with pipx
   ```

2. Initialize the config (this must happen *before* the agent is loaded —
   `hma serve` refuses to start without one):

   ```bash
   hma init
   ```

3. Copy the plist into your per-user LaunchAgents directory and fix the
   `hma` path from step 1:

   ```bash
   mkdir -p ~/Library/LaunchAgents
   cp deploy/com.holdmyagent.arbiter.plist ~/Library/LaunchAgents/
   sed -i '' "s#/usr/local/bin/hma#$(which hma)#" \
     ~/Library/LaunchAgents/com.holdmyagent.arbiter.plist
   ```

4. Load it:

   ```bash
   launchctl load ~/Library/LaunchAgents/com.holdmyagent.arbiter.plist
   ```

5. Verify:

   ```bash
   curl -fsS localhost:8000/health
   tail -f /tmp/holdmyagent.log /tmp/holdmyagent.err
   ```

## Managing the service

```bash
# stop / start without unloading
launchctl kickstart -k gui/$(id -u)/com.holdmyagent.arbiter

# unload entirely (also stops it from starting at next login)
launchctl unload ~/Library/LaunchAgents/com.holdmyagent.arbiter.plist
```

`KeepAlive=true` means launchd restarts the process if it exits for any
reason (including a clean `hma serve` exit), so use `unload` rather than
`kill` when you actually want it to stay down.

## Updating

```bash
pip install --user --upgrade holdmyagent
launchctl kickstart -k gui/$(id -u)/com.holdmyagent.arbiter
```

Database migrations run automatically on the next start. If `pip`
installed a new binary at a different path (rare, but possible after a
Python version change), re-run the `sed` step and reload the plist.
