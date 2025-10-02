# Testing the Event System - Quick Guide

## ✅ Application is Starting!

The application is currently compiling and will launch shortly. Here's what to do next:

## 📋 Testing Steps

### 1. Open Developer Tools
Once the Tauri window opens:
- Press **F12** to open DevTools
- Navigate to the **Console** tab
- Keep this open to see event logs

### 2. Navigate to Dashboard
- The Dashboard should load automatically
- You'll see the main interface with:
  - Quick Scan section
  - Available Workflows
  - System Status
  - Recent Activity

### 3. Test Real-Time Workflow Events

**Option A: Run a Workflow from Dashboard**
1. Enter a target URL (e.g., `example.com`)
2. Select a workflow from the dropdown
3. Click "Run Workflow" button
4. **Watch the Console** - You should see:
   ```
   📡 Workflow started: <execution-id>
   🔧 Step started: <step-name>
   📊 Workflow progress: <execution-id> <progress>%
   ✓ Step completed: <step-name>
   ✅ Workflow completed: <execution-id>
   ```

**Option B: Run a Workflow from Scans Page**
1. Click "Scans" in the sidebar
2. Click "New Scan" button
3. Fill in the scan details
4. Click "Create Scan"
5. **Watch the Console** for scan events:
   ```
   📡 Scan started: <scan-id>
   📊 Scan progress: <scan-id> <progress>%
   ✅ Scan completed: <scan-id>
   ```

### 4. What to Look For

**In Console:**
- ✅ Event logs with 📡, 📊, ✅, ❌ emojis
- ✅ Execution IDs matching between events
- ✅ Progress updates with percentages
- ✅ Step-by-step execution logs

**In UI:**
- ✅ Progress bars updating in real-time
- ✅ Status badges changing (pending → running → completed)
- ✅ Scan list updating without page refresh
- ✅ "Recent Activity" section updating automatically

### 5. Test Multiple Concurrent Executions

1. Open Dashboard
2. Start a workflow
3. Immediately navigate to Scans page
4. Start another scan
5. **Watch Console** - You should see interleaved events:
   ```
   📡 Workflow started: abc-123
   📡 Scan started: def-456
   📊 Workflow progress: abc-123 25%
   📊 Scan progress: def-456 10%
   📊 Workflow progress: abc-123 50%
   📊 Scan progress: def-456 30%
   ✅ Workflow completed: abc-123
   ✅ Scan completed: def-456
   ```

### 6. Test Error Handling

1. Try running a workflow with an invalid target
2. **Watch Console** for error events:
   ```
   ❌ Workflow failed: <execution-id>
   ❌ Scan failed: <scan-id>
   ```

## 🐛 Troubleshooting

### If You Don't See Events:
1. Check Console is open (F12)
2. Make sure you're on the Console tab
3. Clear console filters (click the filter icon)
4. Try running a workflow again

### If UI Doesn't Update:
1. Check the Network tab - should see no polling requests
2. Verify React Query DevTools (if installed)
3. Check browser console for errors

### If Workflows Don't Run:
1. Check if tools are discovered (go to Tools page)
2. Verify working directory exists
3. Check backend logs in terminal

## 📊 Expected Behavior

### ✅ Working Correctly:
- Events appear in console immediately when actions happen
- UI updates without page refresh
- Progress bars move smoothly
- Status badges change in real-time
- No constant polling visible in Network tab

### ❌ Not Working:
- No console logs when running workflows
- UI requires page refresh to show updates
- Progress bars don't move
- Status stays on "pending" forever
- Network tab shows constant polling requests

## 🎯 Success Criteria

The event system is working if:
1. ✅ Console shows event logs with execution IDs
2. ✅ UI updates in real-time without refresh
3. ✅ Progress tracking works accurately
4. ✅ Multiple concurrent executions tracked separately
5. ✅ Error states handled gracefully

## 📝 Notes

- Events are emitted from Rust backend via Tauri
- Frontend listens using `@tauri-apps/api/event`
- React Query cache updated on event receipt
- No mock data - all data comes from actual backend
- Events include timestamps for debugging

## 🚀 Next Actions After Testing

If everything works:
1. Mark Task 4 as complete
2. Document any issues found
3. Consider adding toast notifications
4. Add log streaming component
5. Implement progress visualization

If issues found:
1. Note which events don't appear
2. Check if event names match backend
3. Verify event payload structure
4. Test event cleanup (no memory leaks)
5. Report findings for fixes

---

**Current Status**: App is compiling... ⏳
**Wait for**: Tauri window to open
**Then**: Follow testing steps above
**Goal**: Verify all events work end-to-end
