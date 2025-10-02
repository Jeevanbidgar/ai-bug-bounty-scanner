# Frontend-to-Rust Backend Integration Fixes

## Critical Issues Found and How to Fix Them

### 1. **api.ts Service Issues**

**Problem**: The api.ts has TypeScript errors and inconsistent data handling.

**Solution**: The file has already been updated with:
- Proper TypeScript types matching Rust backend
- All API calls use Tauri commands (`invoke`)
- Mock data fallback for development
- Proper error handling

**Status**: ✅ Already fixed (see `frontend/src/services/api.ts`)

---

### 2. **Dashboard.tsx Issues**

**Problems**:
- Accessing `response.data.data` instead of just `response.data`
- System metrics structure mismatch
- Undefined property access

**Fixes Needed**:

```typescript
// WRONG:
const scans = scansResponse?.data?.data || []

// CORRECT:
const scans = scansResponse || []

// And for query definitions:
const { data: scansResponse } = useQuery({
  queryFn: async () => {
    const response = await apiService.getScans()
    return response.data || []
  }
})
```

**Fix the data access patterns** throughout Dashboard.tsx:
- Remove `.data.data` access patterns
- Use proper null coalescing
- Handle undefined systemMetrics properly

---

### 3. **Scans Page Issues**

**Problems**:
- Still importing websocket service
- Error handling inconsistency
- Workflow execution result structure

**Fixes Needed**:

```typescript
// Import the Tauri event service instead
import { tauriEventService } from '../services/tauriEvents'

// Update workflow execution mutation:
const workflowMutation = useMutation({
  mutationFn: async ({ workflowId, inputs }) => {
    const response = await apiService.executeWorkflow(workflowId, inputs)
    return response.data  // This returns { execution_id: string }
  },
  onSuccess: (data) => {
    // data.execution_id contains the execution ID
    console.log('Workflow started:', data.execution_id)
    queryClient.invalidateQueries({ queryKey: ['scans'] })
  }
})
```

---

### 4. **Event System Migration**

**Current**: Uses Socket.IO (`websocket.ts`)
**Target**: Use Tauri Events (`tauriEvents.ts`)

**Changes needed in all pages**:

```typescript
// OLD (Remove):
import { websocketService } from '../services/websocket'
websocketService.connect()
websocketService.on('scan_progress_update', callback)

// NEW (Use instead):
import { tauriEventService } from '../services/tauriEvents'
await tauriEventService.connect()
tauriEventService.on('scan_progress_update', callback)
```

---

### 5. **Tools Page Issues**

**Problems**:
- Tool structure mismatch
- Refresh tools doesn't return proper data

**Fix**:

```typescript
const refreshToolsMutation = useMutation({
  mutationFn: () => apiService.refreshToolsStatus(),
  onSuccess: () => {
    // Invalidate and refetch tools
    queryClient.invalidateQueries({ queryKey: ['tools'] })
  }
})
```

---

### 6. **Reports Page Issues**

**Problems**:
- Report creation doesn't return proper structure
- Download functionality not implemented

**Temporary workaround**:

```typescript
// Disable download button until implemented
<Button 
  disabled={true} 
  title="Download not yet implemented in Rust backend"
>
  Download
</Button>
```

---

## Step-by-Step Migration Checklist

### Phase 1: Fix API Service ✅
- [x] Update all TypeScript types
- [x] Implement all Tauri commands
- [x] Add mock data fallback
- [x] Remove HTTP calls

### Phase 2: Update Dashboard
- [ ] Fix data access patterns
- [ ] Remove `.data.data` patterns
- [ ] Handle system metrics properly
- [ ] Fix undefined access errors

### Phase 3: Update ScansPage
- [ ] Import tauriEvents instead of websocket
- [ ] Fix workflow execution handling
- [ ] Update event listeners
- [ ] Fix scan status updates

### Phase 4: Update ToolsPage
- [ ] Fix tool data structure
- [ ] Update refresh mutation
- [ ] Handle tool status properly

### Phase 5: Update ReportsPage
- [ ] Fix report listing
- [ ] Update report creation
- [ ] Disable unavailable features

### Phase 6: Replace Event System
- [ ] Update all event imports
- [ ] Replace websocket with tauriEvents
- [ ] Test real-time updates

---

## Quick Fix Script

To quickly fix the most critical issues:

1. **Fix Dashboard data access**:
```bash
# In Dashboard.tsx, replace all:
const scans = scansResponse || []
const tools = toolsResponse || []
```

2. **Fix Scans page imports**:
```bash
# Replace:
import { websocketService } from '../services/websocket'
# With:
import { tauriEventService } from '../services/tauriEvents'
```

3. **Test the app**:
```bash
npm run tauri dev
```

---

## Testing Procedure

1. **Start the app**: `npm run tauri dev`
2. **Check Dashboard**: Should load without errors
3. **Check Tools page**: Should list tools
4. **Create a scan**: Should create successfully
5. **Execute workflow**: Should start and show progress
6. **Check console**: No errors should appear

---

## Common Errors and Solutions

### Error: "Cannot read property 'data' of undefined"
**Cause**: Accessing nested `.data.data`
**Fix**: Use `response.data` or just `response` depending on context

### Error: "invoke is not a function"
**Cause**: Not in Tauri environment
**Fix**: Code already handles this with mock data

### Error: "Command not found"
**Cause**: Rust backend command not implemented
**Fix**: Check `src-tauri/src/main.rs` for registered commands

### Error: "WebSocket connection failed"
**Cause**: Still using old websocket service
**Fix**: Replace with tauriEvents service

---

## Files That Need Updates

1. ✅ `frontend/src/services/api.ts` - **DONE**
2. ✅ `frontend/src/services/tauriEvents.ts` - **DONE** (already exists)
3. ⚠️  `frontend/src/pages/Dashboard.tsx` - **NEEDS FIX**
4. ⚠️  `frontend/src/pages/ScansPage.tsx` - **NEEDS FIX**
5. ⚠️  `frontend/src/pages/ToolsPage.tsx` - **NEEDS FIX**
6. ⚠️  `frontend/src/pages/ReportsPage.tsx` - **NEEDS FIX**
7. ✅ `frontend/src/App.tsx` - **WORKING**
8. ✅ `frontend/src/hooks/useWorkflowEvents.ts` - **WORKING**

---

## Next Steps

Run this command to see the current status:
```bash
npm run tauri dev
```

Then fix errors one by one following this guide.
