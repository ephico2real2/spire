# CMTC local recovery checkpoint

This commit preserves the unfinished isolated implementation at the user's explicit request. It is a recovery commit, not a release or proof of end-to-end workload mTLS.

Claude Code Opus5.5High session `c03d57db-e2bf-4848-ab73-3f2696a27d2f` stopped on its monthly spend limit. Preserve the original mixed Codex/Cursor/Claude work and test failures. Primary Codex now owns continuation. Cursor Grok4.7ExtraHigh reviews the node-name port without source edits.

Use edit → run against cmtc-a/cmtc-b → test traffic, failures and recovery → package the verified change. Preserve the native ClusterMesh path, signer state, security guards and owned lab resources. CI and publication remain deferred. No ztunnel proxy is running in either cluster at this checkpoint.

Initial cache-expiry checks passed affected race/vet after explicit alias-size budget correction. Follow-up dynamic-role/delegate expiry regressions fail before fixes and pass afterward:17 top-level/151subtests,zero failures/skips,vet. These remain source checks. Live expiry/recovery remains open.

Original base HEAD: `28f6b8d84ade21c6accb32ba9689a3bdf64877ec`.
