# Sprint: Documentation Cleanup & Tool Audit  

**Date:** 7 July 2026  
**Type:** Temporary/Corrective Sprint  
**Commander:** Current  

## Goal  
Correct outdated information in .md files, archive incorrect content, create GitHub repo for Graphify, reorganize .md file structure, and audit subagent tools.

## Work Items  

### Item 1: .md Documentation Audit & Consolidation  
- **Assigned to:** intel (research) → strike (implement fixes)  
- **Description:** Review all .md files in the project for outdated, incorrect, or contradictory information. Archive old sprint handoffs (Sprint 7, 8 handoffs reference pre-Sprint-9 state). Update MVP_SCOPE.md to reflect items that were deferred but are now implemented. Update ROADMAP.md if needed.  
- **Expected output:** intel report in `backend/reports/intel/doc-audit-2026-07-07.md` listing all files needing changes with specific recommendations. Strike then implements fixes and archives outdated content.

### Item 2: Create GitHub Repo: Graphify-Labs/graphify  
- **Assigned to:** strike  
- **Description:** Create a local git repository structure for https://github.com/Graphify-Labs/graphify. Write README.md, basic structure, and detailed notes from the subagent about what was created, why, and next steps. The repo should be initialized locally in a temporary location with instructions for pushing to GitHub.  
- **Expected output:** Local repo created at `/home/jpc/Documents/Cybersecurity (Temp)/graphify/` with README.md and AGENT_NOTES.md (detailed notes from the subagent). The AGENT_NOTES.md should explain every decision made so the user can hand it to another AI for continued maintenance.

### Item 3: .md Organization Strategy  
- **Assigned to:** bookkeeper  
- **Description:** Propose a strategy for organizing all .md files that are currently scattered across the project root, Additional Instructions/, External/Archive/, ARCHIVED/, and other locations. Recommend a dedicated folder (e.g., `docs/`), which files should move there, and which files need symlinks/shortcuts at their original locations.  
- **Expected output:** Bookkeeper report in `backend/reports/bookkeeping/md-organization-2026-07-07.md`

### Item 4: Subagent Tool Audit  
- **Assigned to:** auditor + intel  
- **Description:** Verify that the tools and commands available to subagents actually work. Test the justfile commands, audit scripts, and check for gaps. Intel should research whether new tools/scripts are needed.  
- **Expected output:** Auditor report in `backend/reports/audits/tool-audit-2026-07-07.md` and intel report in `backend/reports/intel/tool-gap-analysis-2026-07-07.md`

## Verification  
- All sprint-related .md files are accurate and up-to-date  
- Outdated content is archived with clear "ARCHIVED" markers  
- Graphify repo structure is ready to push to GitHub  
- .md organization recommendation is actionable  
- Tool audit confirms working state or identifies gaps  
