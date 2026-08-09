package app

func mergeOptional(base optionalString, overlays ...optionalString) optionalString {
	merged := base
	for _, overlay := range overlays {
		if overlay.present {
			merged = overlay
		}
	}
	return merged
}

func mergeProbe(base probePatch, overlays ...probePatch) probePatch {
	merged := base
	for _, overlay := range overlays {
		merged.Portal = mergeOptional(merged.Portal, overlay.Portal)
		merged.HostID = mergeOptional(merged.HostID, overlay.HostID)
		merged.SSOFile = mergeOptional(merged.SSOFile, overlay.SSOFile)
		merged.DebugLog = mergeOptional(merged.DebugLog, overlay.DebugLog)
	}
	return merged
}

func mergeAuth(base authPatch, overlays ...authPatch) authPatch {
	merged := base
	for _, overlay := range overlays {
		merged.Portal = mergeOptional(merged.Portal, overlay.Portal)
		merged.HostID = mergeOptional(merged.HostID, overlay.HostID)
		merged.Browser = mergeOptional(merged.Browser, overlay.Browser)
		merged.BrowserPath = mergeOptional(merged.BrowserPath, overlay.BrowserPath)
		merged.BrowserProfileDir = mergeOptional(merged.BrowserProfileDir, overlay.BrowserProfileDir)
		merged.Timeout = mergeOptional(merged.Timeout, overlay.Timeout)
		merged.DebugLog = mergeOptional(merged.DebugLog, overlay.DebugLog)
	}
	return merged
}

func mergeServe(base servePatch, overlays ...servePatch) servePatch {
	merged := base
	for _, overlay := range overlays {
		merged.Listen = mergeOptional(merged.Listen, overlay.Listen)
		merged.Portal = mergeOptional(merged.Portal, overlay.Portal)
		merged.Gateway = mergeOptional(merged.Gateway, overlay.Gateway)
		merged.HostID = mergeOptional(merged.HostID, overlay.HostID)
		merged.Browser = mergeOptional(merged.Browser, overlay.Browser)
		merged.BrowserPath = mergeOptional(merged.BrowserPath, overlay.BrowserPath)
		merged.BrowserProfileDir = mergeOptional(merged.BrowserProfileDir, overlay.BrowserProfileDir)
		merged.Timeout = mergeOptional(merged.Timeout, overlay.Timeout)
		merged.DebugLog = mergeOptional(merged.DebugLog, overlay.DebugLog)
	}
	return merged
}
